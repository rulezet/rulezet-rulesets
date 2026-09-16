rule CISA_10454006_01 : SUBMARINE trojan backdoor remote_access_trojan remote_access information_gathering exploitation determines_c2_server controls_local_machine compromises_data_integrity
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10452108"
       Date = "2023-06-29"
       Last_Modified = "20230711_1500"
       Actor = "n/a"
       Family = "SUBMARINE"
       Capabilities = "determines-c2-server controls-local-machine compromises-data-integrity"
       Malware_Type = "trojan backdoor remote-access-trojan"
       Tool_Type = "remote-access information-gathering exploitation"
       Description = "Detects SUBMARINE Barracuda backdoor samples"
       SHA256_1 = "81cf3b162a4fe1f1b916021ec652ade4a14df808021eeb9f7c81c8d2326bddab"
   strings:
       $s1 = { 32 35 30 2d 6d 61 69 6c 32 2e 65 63 63 65 6e 74 72 69 63 2e 64 75 63 6b }
       $s2 = { 6f 70 65 6e 73 73 6c 20 61 65 73 2d 32 35 36 }
       $s3 = { 65 63 68 6f 20 2d 6e 20 27 25 73 27 20 7c 20 62 61 73 65 36 34 20 2d 64 }
       $s4 = { 2d 69 76 }
       $s5 = { 48 65 6c 6c 6f 20 25 73 20 5b 25 73 5d 2c 20 70 6c 65 61 73 65 64 20 74 6f 20 6d 65 65 74 20 79 6f 75 }
       $s6 = { e8 47 fa ff }
       $s7 = { 63 6f 6d 6d 61 6e 64 }
       $s8 = { 2d 69 76 20 36 39 38 32 32 62 36 63 }
       $s9 = { 73 65 6e 64 }
       $s10 = { 73 6f 63 6B 65 74 }
       $s11 = { 63 6f 6e 6e 65 63 74 }
   condition:
       filesize < 15KB and 8 of them
}