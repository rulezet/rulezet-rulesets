rule Uptycs_Ransomware_RTM_Locker {
    meta:
        malware_name = "RANSOMWARE"
        description = "Ransomware is a malware that encrypts sensitive information on your system and asks for ransom in exchange for restoring the encrypted data."
        author = "Uptycs Inc"
        version = "1"
    strings:
        $Ransomware_RTM_Locker_0 = "esxcli vm process list"  ascii wide
        $Ransomware_RTM_Locker_1 = "vmlist.tmp.txt"  ascii wide
        $Ransomware_RTM_Locker_2 = "esxcli vm process kill"  ascii wide
        $Ransomware_RTM_Locker_3 = "!!! Warning!!!"  ascii wide
        $Ransomware_RTM_Locker_4 = "Your network is infected by the RTM Locker command"  ascii wide
    condition:
        all of ($Ransomware_RTM_Locker*)
}