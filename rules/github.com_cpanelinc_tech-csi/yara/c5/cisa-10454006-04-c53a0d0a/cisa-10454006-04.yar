rule CISA_10454006_04 : SUBMARINE trojan backdoor hides_artifacts hides_executing_code infects_files installs_other_components remote_access exploitation
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10454006"
       Date = "2023-07-05"
       Last_Modified = "20230711_1500"
       Actor = "n/a"
       Family = "SUBMARINE"
       Capabilities = "hides-artifacts hides-executing-code infects-files installs-other-components"
       Malware_Type = "trojan backdoor"
       Tool_Type = "remote-access exploitation"
       Description = "Detects SUBMARINE launcher script samples"
       SHA256_1 = "b98f8989e8706380f779bfd464f3dea87c122651a7a6d06a994d9a4758e12e43"
   strings:
       $s1 = { 73 6c 65 65 70 }
       $s2 = { 7c 62 61 73 65 36 34 20 2d 64 }
       $s3 = { 4c 44 5f 50 52 45 4c 4f 41 44 }
       $s4 = { 2f 68 6f 6d 65 2f 70 72 6f 64 75 63 74 2f 63 6f 64 65 2f 66 69 72 6d 77 61 72 65 2f 63 75 72 72 65 6e 74 2f 73 62 69 6e 2f 73 6d 74 70 63 74 6c 20 72 65 73 74 61 72 74 }
       $s5 = { 65 63 68 6f 20 2d 6e 20 27 }
       $s6 = { 73 68 }
       $s7 = { 23 21 20 2f 62 69 6e 2f 73 68 }
   condition:
       filesize < 2KB and 6 of them
}