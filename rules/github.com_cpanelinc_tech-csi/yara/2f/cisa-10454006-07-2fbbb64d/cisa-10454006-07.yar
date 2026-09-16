rule CISA_10454006_07 : SUBMARINE trojan dropper exploit_kit evades_av hides_executing_code hides_artifacts exploitation
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10454006"
       Date = "2023-07-11"
       Last_Modified = "20230711_1830"
       Actor = "n/a"
       Family = "SUBMARINE"
       Capabilities = "evades-av hides-executing-code hides-artifacts"
       Malware_Type = "trojan dropper exploit-kit"
       Tool_Type = "exploitation"
       Description = "Detects ESG FileName exploit samples"
       SHA256 = "8695945155d3a87a5733d31bf0f4c897e133381175e1a3cdc8c73d9e38640239"
   strings:
       $s1 = { 7c 20 62 61 73 65 36 34 20 2d 64 20 7c 20 73 68 }
       $s2 = { 65 63 68 6f 20 2d 6e }
       $s3 = { 59 32 46 30 49 43 39 32 59 58 49 76 64 47 31 77 4c 33 49 67 66 43 42 69 59 58 4e 6c 4e 6a 51 67 4c 57 51 67 4c 57 6b 67 66 43 42 30 59 58 49 67 }
   condition:
       filesize < 1KB and all of them
}