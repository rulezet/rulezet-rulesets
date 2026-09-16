rule linux_mal_suterusu_rootkit {
    meta:
        description = "Detects open source rootkit named suterusu"
        hash1 = "7e5b97135e9a68000fd3efee51dc5822f623b3183aecc69b42bde6d4b666cfe1"
        hash2 = "7b48feabd0ffc72833043b14f9e0976511cfde39fd0174a40d1edb5310768db3"
        author = "Lacework Labs"
        ref = "https://www.lacework.com/blog/hcrootkit-sutersu-linux-rootkit-analysis/"
    strings:
        $a1 = "suterusu"
        $a3 = "srcversion="
        $a4 = "Hiding PID"
        $a5 = "/proc/net/tcp"
    condition:
        uint32(0)==0x464c457f and all of them
}