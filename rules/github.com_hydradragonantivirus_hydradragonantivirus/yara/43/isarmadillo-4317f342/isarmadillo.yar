import "pe"
rule IsArmadillo
{
		meta:
		author="_pusher_"
		date = "2016-06"
	strings: 
		$a0 = { 50 44 41 54 41 30 30 30 }
		$a1 = { 00 00 00 52 36 30 30 39 0D 0A }
	condition:
	($a0 or $a1) and
	(pe.linker_version.major == 83) and (pe.linker_version.minor == 82 ) and
(


	pe.entry_point == 0x97D8 or 	pe.entry_point == 0x894E or 	pe.entry_point == 0x9E5E or 	pe.entry_point == 0xA1EF or 	pe.entry_point == 0xA3A8 or 	pe.entry_point == 0xA53F or 	pe.entry_point == 0x2AB19 or 	pe.entry_point == 0x30000 or  	pe.entry_point == 0x2C743 or  	pe.entry_point == 0x32000 or  	pe.entry_point == 0x38BF2 or  	pe.entry_point == 0x3CD93 or  	pe.entry_point == 0x3CDB3 or  	pe.entry_point == 0x3CCB3 or  	pe.entry_point == 0x41733 or  	pe.entry_point == 0x44000 or  	pe.entry_point == 0x43000 or  	pe.entry_point == 0x3AE97 or  	pe.entry_point == 0x42000 or  	pe.entry_point == 0xE6C0A or  	pe.entry_point == 0x68000 or  	pe.entry_point == 0x3D000 or  	pe.entry_point == 0x5A000 or  	pe.entry_point == 0x62000 or  	pe.entry_point == 0x68F85 or  	pe.entry_point == 0x63000 or  	pe.entry_point == 0x5487B or 	pe.entry_point == 0x31000 or 	pe.entry_point == 0x6E05D or 	pe.entry_point == 0x6D540 or 	pe.entry_point == 0x6EDAF or 	pe.entry_point == 0x8312F or 	pe.entry_point == 0x8812F or 	pe.entry_point == 0x8912F or 	pe.entry_point == 0x8A12F or 	pe.entry_point == 0x8B12F or 	pe.entry_point == 0x6DF65 or 	pe.entry_point == 0x6F1FE )

}