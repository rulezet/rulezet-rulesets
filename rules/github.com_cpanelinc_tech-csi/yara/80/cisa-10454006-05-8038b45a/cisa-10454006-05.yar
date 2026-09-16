rule CISA_10454006_05 : SUBMARINE trojan backdoor remote_access_trojan compromises_data_integrity cleans_traces_of_infection hides_artifacts installs_other_components remote_access exploitation
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10454006"
       Date = "2023-07-05"
       Last_Modified = "20230711_1500"
       Actor = "n/a"
       Family = "SUBMARINE"
       Capabilities = "compromises-data-integrity cleans-traces-of-infection hides-artifacts installs-other-components"
       Malware_Type = "trojan backdoor remote-access-trojan"
       Tool_Type = "remote-access exploitation"
       Description = "Detects SUBMARINE launcher script samples"
       SHA256_1 = "cc131dd1976a47ee3b631a136c3224a138716e9053e04d8bea3ee2e2c5de451a"
   strings:
       $s1 = { 4c 44 5f 50 52 45 4c 4f 41 44 }
       $s2 = { 23 21 20 2f 62 69 6e 2f 73 68 }
       $s3 = { 4c 44 5f 50 52 45 4c 4f 41 44 3d 2f 62 6f 6f 74 2f 6f 73 5f 74 6f 6f 6c 73 2f 6c 69 62 75 74 69 6c 2e 73 6f 20 65 78 65 63 }
       $s4 = { 3e 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e 26 31 }
       $s5 = { 62 73 6d 74 70 64 20 63 6f 6e 74 72 6f 6c 20 73 63 72 69 70 74 }
       $s6 = { 42 53 4d 54 50 44 5f 50 49 44 }
       $s7 = { 2f 72 65 6c 6f 61 64 2f 72 65 73 74 61 72 74 }
   condition:
       filesize < 6KB and 6 of them
}