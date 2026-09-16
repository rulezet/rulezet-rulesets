rule Compromised_DLL_3CX {
  meta:
    author      = "Daniel Mayer (daniel@stairwell.com)"
    description = "A rule for detecting a malicious DLL included in legitimate 3CX installers"
    version     = "1.0"
    date        = "2023-03-29"
    reference1  = "https://twitter.com/DanielStepanic/status/1641115302246207489"
    reference2  = "https://twitter.com/DanielStepanic/status/1641115302246207489"
    sample1     = "aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"

  strings:
    $s_tutma     = "__tutma"
    $s_tutmc     = "__tutmc"
    $s_manifest  = "manifest" wide
    $s_crypto    = "Software\\Microsoft\\Cryptography" wide
    $s_guid      = "MachineGuid"
    $s_github    = "raw.githubusercontent.com" wide
    $url         = "https://raw.githubusercontent.com/IconStorages/images" wide
    $lcg_chunk_1 = {
      41 81 C0 87 D6 12 00        02 C8                       49 C1 E9 20                 41 88 4B 03                 4D 03 D1                    8B C8                       45 8B CA                    C1 E1 05                    33 C1                       41 69 D0 7D 50 BF 12        8B C8                       C1 E9 07                    33 C1                       8B C8                       C1 E1 16                  }

  condition:
    filesize < 500KB and (all of ($s*) or (3 of ($s*) and $lcg_chunk_1) or $url)
}