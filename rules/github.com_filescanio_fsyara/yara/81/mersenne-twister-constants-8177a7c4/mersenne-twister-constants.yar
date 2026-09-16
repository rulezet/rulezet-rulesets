import "pe"
rule mersenne_twister_constants : hardened
{
	meta:
		score = 50

	strings:
		$0x6C078965 = {65 89 07 6C}
		$0x9908B0DF = {DF B0 08 99}
		$0x9D2C5680 = {80 56 2C 9D}
		$0xEFC60000 = {00 00 C6 EF}
		$0xFF3A58AD = {AD 58 3A FF}
		$aa = {FF3A58AD}
		$0xB5026F5AA96619E9 = {E9 19 66 A9 C7 45 ?? 5A 6F 02 B5}
		$0x71D67FFFEDA60000 = {00 00 A6 ED ?? ?? FF 7F D6 71}

	condition:
		pe.is_pe and 2 of them
}