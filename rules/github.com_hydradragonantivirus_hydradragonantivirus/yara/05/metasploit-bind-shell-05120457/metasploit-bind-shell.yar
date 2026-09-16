rule metasploit_bind_shell {
    meta:
        author = "FDD @ Cuckoo Sandbox"
        description = "Rule for metasploit's bind shell shellcode"
        name = "Metasploit bind shell payload"

    strings:
        $s1 = { fce8 8?00 0000 60 }             $s2 = { 648b ??30 }                     $s3 = { 4c77 2607 }                     $s4 = { 2980 6b00 }                     $s5 = { ea0f dfe0 }                     $s6 = { c2db 3767 }                     $s7 = { b7e9 38ff }                     $s8 = { 74ec 3be1 }             
    condition:
        all of them and filesize < 5KB
}