rule CISA_10454006_03 : SUBMARINE trojan backdoor loader rootkit virus controls_local_machine hides_artifacts infects_files installs_other_components remote_access exploitation information_gathering
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10454006"
       Date = "2023-07-03"
       Last_Modified = "20230711_1500"
       Actor = "n/a"
       Family = "SUBMARINE"
       Capabilities = "controls-local-machine hides-artifacts infects-files installs-other-components"
       Malware_Type = "trojan backdoor loader rootkit virus"
       Tool_Type = "remote-access exploitation information-gathering"
       Description = "Detects SUBMARINE launcher script samples"
       SHA256_1 = "bbbae0455f8c98cc955487125a791052353456c8f652ddee14f452415c0b235a"
   strings:
       $s1 = { 73 65 64 20 2d 69 }
       $s2 = { 4c 44 5f 50 52 45 4c 4f 41 44 3d }
       $s3 = { 6c 69 62 75 74 69 6c 2e 73 6f }
       $s4 = { 2f 73 62 69 6e 2f 73 6d 74 70 63 74 6c }
       $s5 = { 2f 62 6f 6f 74 2f 6f 73 5f 74 6f 6f 6c 73 }
       $s6 = { 72 6d 20 2d 72 66 }
       $s7 = { 62 61 73 65 36 34 20 2d 64 }
       $s8 = { 7c 73 68 }
       $s9 = { 72 65 73 74 61 72 74 }
       $s10 = { 2f 64 65 76 2f 6e 75 6c 6c }
       $s11 = { 23 21 20 2f 62 69 6e 2f 73 68 }
       $s12 = { 62 61 73 65 36 34 }
   condition:
       filesize < 2KB and all of them
}