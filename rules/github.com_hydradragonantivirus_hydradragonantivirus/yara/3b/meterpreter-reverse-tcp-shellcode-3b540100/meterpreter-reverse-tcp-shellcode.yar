rule meterpreter_reverse_tcp_shellcode {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Rule for metasploit's  meterpreter reverse tcp raw shellcode"

    strings:
        $s1 = { fce8 8?00 0000 60 }             $s2 = { 648b ??30 }                     $s3 = { 4c77 2607 }                     $s4 = "ws2_"                            $s5 = { 2980 6b00 }                     $s6 = { ea0f dfe0 }                     $s7 = { 99a5 7461 }             
    condition:
        all of them and filesize < 5KB
}