rule Rootkit_Linux_Libprocesshider {
    meta:
        description = "Detects libprocesshider Linux process hiding library"
        author = "mmuir@cadosecurity.com"
        date = "2202-05-12"
        license = "Apache License 2.0"
    strings:
        $str1 = "readdir"
        $str2 = "/proc/self/fd/"
        $str3 = "processhider.c"
        $str4 = "get_process_name"
        $str5 = "/proc/%s/stat"
        $str6 = "process_to_filter"
        $str7 = "get_dir_name"
    condition:
        uint32(0) == 0x464c457f and
        uint8(16) == 0x0003 and
        all of them
}