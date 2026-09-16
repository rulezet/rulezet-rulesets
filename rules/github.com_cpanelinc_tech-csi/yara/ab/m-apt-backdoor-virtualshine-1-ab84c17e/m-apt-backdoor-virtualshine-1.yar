rule M_APT_Backdoor_VIRTUALSHINE_1 {
    meta:
        author = "Mandiant"
    strings:
        $str1 = "/dev/vsock"
        $str2 = "/vmfs/devices/char/vsock/vsock"
        $str3 = "nds4961l <cid> <vport>"
        $str4 = "[!] VMCISock_GetAFValue()."
        $str5 = "[+] Connected to server.[ %s:%s ]"
        $str6 = "TERM=xterm"
        $str7 = "PWD=/tmp/"
    condition:
        uint32(0) == 0x464C457F and all of them
}