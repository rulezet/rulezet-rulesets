rule warning_package_manager_embedded {
    meta:
        is_exploit = true
        is_warning = false
        is_feature = false
        rank = 1
        revision = "2"
        date = "July 29 2015"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "Office package manager may load unsafe content such as shell scripts"
    strings:
        $s1 = "0003000C-0000-0000-c000-000000000046" nocase
        $s2 = "0c00030000000000c000000000000046"
        $s3 = {0c00030000000000c000000000000046}
	$s4 = "20a70df22fc0ce11927b0800095ae340" nocase
	$s5 = {20a70df22fc0ce11927b0800095ae340}
        $s7 = "Packager Shell Object" ascii wide
        
    condition:
        1 of them
    }