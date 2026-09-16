import "pe"
rule Mersenne_Twister : hardened
{
	meta:
		reference = "https://en.wikipedia.org/wiki/Mersenne_Twister"
		score = 50

	strings:
		$initialize_loop = {
            48 81 ?? 70 02 00 00
        }
		$initialize_seed_processing = {
            C1 ?? 1E [0-3] 33 C8 [0-8] (69 ?? 65 89 07 6C | 0F AF ??) [0-9] 03
        }
		$random_btr_op = {
            0F BA (F1 | F0) 1F
        }
		$const_1 = {
            65 89 07 6C
        }
		$const_2 = {
            DF B0 08 99
        }

	condition:
		pe.is_pe and uint16( 0 ) == 0x5A4D and ( $initialize_loop ) and ( $random_btr_op ) and ( $const_1 ) and ( $const_2 ) and ( $initialize_seed_processing )
}