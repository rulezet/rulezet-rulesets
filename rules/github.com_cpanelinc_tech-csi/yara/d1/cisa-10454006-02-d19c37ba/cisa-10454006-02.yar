import "math"
rule CISA_10454006_02 : SUBMARINE trojan backdoor exploitation hides_artifacts prevents_artifact_access
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10454006"
       Date = "2023-06-29"
       Last_Modified = "20230711_1500"
       Actor = "n/a"
       Family = "SUBMARINE"
       Capabilities = "hides-artifacts prevents-artifact-access"
       Malware_Type = "trojan backdoor"
       Tool_Type = "exploitation"
       Description = "Detects encoded GZIP archive samples"
       SHA256_1 = "6dd8de093e391da96070a978209ebdf9d807e05c89dba13971be5aea2e1251d0"
   strings:
       $s1 = { 48 34 73 49 41 41 41 41 41 41 41 41 41 2b 30 61 }
       $s2 = { 44 44 44 41 67 50 39 2f 2b 43 38 47 70 2f 36 63 41 46 41 41 41 41 3d 3d 0a}
       $s3 = { 37 56 4d 70 56 58 4f 37 2b 6d 4c 39 78 2b 50 59 }
   condition:
       filesize < 6KB and 3 of them and (math.entropy(0,filesize) > 5.8)
}