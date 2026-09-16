rule warning_vb_macro {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 3
		revision = "2"
		date = "Oct 5 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Visual Basic macro"
	strings:
		$s1 = "Name=\"VBAProject\"" nocase
		$s2 = "OLE Automation" wide nocase
		$s3 = "Visual Basic For Applications" wide nocase
		$s5 = "VBA6\\VBE6.DLL" wide nocase
		$s6 = "000204EF-0000-0000-C000-000000000046" ascii wide
		$s7 = "00020430-0000-0000-C000-000000000046" ascii wide
		$s8 = {000204EF00000000C000000000000046}
		$s9 = {0002043000000000C000000000000046}
		$s10 = "000204EF00000000C000000000000046"
		$s11 = "0002043000000000C000000000000046"
		$s12 = "wne:vbaSuppData" nocase
		$s13 = "wne:macroName" nocase

	condition:
            1 of them
}