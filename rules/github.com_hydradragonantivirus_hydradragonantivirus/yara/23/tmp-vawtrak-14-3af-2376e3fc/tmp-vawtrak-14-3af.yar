rule _tmp_vawtrak_14_3af {
	meta:
		description = "Auto-generated rule - file 14_3af.dat"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "f57fd8a48e90a7c061ad9c783935a39a8e41b619fa86a3d5fcdb873635e9f970"
	strings:
		$s1 = "mpress.exe" fullword wide 
		$s2 = "Z:\\fzw6rqq\\j\\gww\\tkclux\\8qt.pdb" fullword ascii 
		$s3 = "PE32, PE32+, .NET Compressor" fullword wide 
		$s4 = "Matcode comPRESSor" fullword wide 
		$s5 = "Copyright (C) 2008, MATCODE Software" fullword wide 
		$s6 = "* 8N'>" fullword ascii 
		$s7 = "!Lyyyyyyyy+!" fullword ascii 
		$s8 = "\\;.TuU" fullword ascii 
		$s9 = "mpress" fullword wide 
		$s10 = "o\"f&i\"Richg&i\"" fullword ascii 
		$s11 = "qg&i\"g&i\"g&i\"9" fullword ascii 
		$s12 = "m\"e&i\"g&i\"_&i\"g&h\"" fullword ascii 
		$s13 = "MATCODE Software" fullword wide 
	condition:
		( uint16(0) == 0x5a4d and filesize < 500KB and ( 10 of ($s*) ) ) or ( all of them )
}