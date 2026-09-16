rule CISA_10454006_06 : SUBMARINE trojan backdoor cleans_traces_of_infection hides_artifacts installs_other_components
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10454006"
       Date = "2023-07-11"
       Last_Modified = "20230727_1200"
       Actor = "n/a"
       Family = "SUBMARINE"
       Capabilities = "cleans-traces-of-infection hides-artifacts installs-other-components"
       Malware_Type = "trojan backdoor"
       Tool_Type = "unknown"
       Description = "Detects SUBMARINE SQL trigger samples"
       SHA256_1 = "2a353e9c250e5ea905fa59d33faeaaa197d17b4a4785456133aab5dbc1d1d5d5"
   strings:
       $s1 = { 54 52 49 47 47 45 52 }
       $s2 = { 43 52 45 41 54 45 }
       $s3 = { 53 45 4c 45 43 54 20 22 65 63 68 6f 20 2d 6e }
       $s4 = { 62 61 73 65 36 34 20 2d 64 20 7c 20 73 68 }
       $s5 = { 72 6f 6f 74 }
       $s6 = { 53 45 54 }
       $s7 = { 45 4e 44 20 49 46 3b }
       $s8 = { 48 34 73 49 41 41 41 41 41 41 41 41 41 2b 30 61 43 33 42 55 }
       $s9 = { 2f 76 61 72 2f 74 6d 70 2f 72 }
       $s10 = { 2f 72 6f 6f 74 2f 6d 61 63 68 69 6e 65 }
   condition:
   filesize < 250KB and all of them
}