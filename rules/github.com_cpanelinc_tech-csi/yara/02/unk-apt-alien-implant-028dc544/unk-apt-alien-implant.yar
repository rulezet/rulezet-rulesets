rule UNK_APT_Alien_Implant {
    meta:
        author = "Exatrack"
        date =   "2023-03-03"
        update =   "2023-03-03"
        description = "Detects an unknown implant from AlienManager family, maybe related to melofee"
        tlp =  "CLEAR"
        sample_hash = "3535f45bbfafda863665c41d97d894c39277dfd9af1079581d28015f76669b88,"

    strings:
        $str_alien_01 = "[+]  Connect %s Successed,Start Transfer..."
        $str_alien_02 = "Alloc buffer to decrypt data error, length == %d."
        $str_alien_03 = "pel_decrypt_msg data error, error"
        $str_alien_04 = "encrypt data error, length == %d."
        $str_alien_05 = "DoRecvOverlapInternal error!"
        $str_alien_06 = "Socks Listen port is %d,Username is %s, password is %s"
        $str_alien_07 = "Start port mapping error! remoteAddr=%s remotePort=%d localAddr=%s localPort=%d"
        $str_alien_08 = "OnCmdSocksStart error!"
        $str_alien_09 = "The master isn't readable!"
        $str_alien_10 = "ConnectBypassSocks proxy:%s:%d error!"
        $str_alien_11 = "ConnectBypassSocks to %s %d"
        $str_alien_12 = "now datetime: %d-%d-%d %d:%d:%d"
        $str_alien_13 = "Not during working hours! Disconnect!"
        $str_alien_14 = "Example: ./AlienReverse --reverse-address=192.168.1.101:80 --reverse-password=123456"
        $str_alien_15 = "Not during working hours! Disconnect!"
        $str_alien_16 = "SocksManager.cpp"
        $str_alien_17 = "connect() in app_connect"
        $str_alien_18 = "They send us %hhX %hhX"
        $str_alien_19 = "your input directory is not exist!"
        $str_alien_20 = "Send data to local error ==> %d.\n"

    condition:
        any of them
}