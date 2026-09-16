rule UNK_APT_Melofee_Installer {
    meta:
        author = "Exatrack"
        date =   "2023-03-15"
        update =   "2023-03-15"
        description = "Detects the installer for melofee malware"
        score =   80
        tlp =  "AMBER"
        source =  "Exatrack"
        sample_hash = "758b0934b7adddb794951d15a6ddcace1fa523e814aa40b55e2d071cf2df81f0"

    strings:
        $str_melofee_installer_01 = "#Script for starting modules"
        $str_melofee_installer_02 = "#End script"
        $str_melofee_installer_03 = "/etc/intel_audio/"
        $str_melofee_installer_04 = "rm -fr /etc/rc.modules"
        $str_melofee_installer_05 = "-i <data file>      Install"
        $str_melofee_installer_06 = "cteate home folder failed"
        $str_melofee_installer_07 = "create rootkit file failed"
        $str_melofee_installer_08 = "create auto start file failed"
        $str_melofee_installer_09 = "Remove Done!"         $str_melofee_installer_10 = "Unkown option %c\n"

    condition:
        any of them
}