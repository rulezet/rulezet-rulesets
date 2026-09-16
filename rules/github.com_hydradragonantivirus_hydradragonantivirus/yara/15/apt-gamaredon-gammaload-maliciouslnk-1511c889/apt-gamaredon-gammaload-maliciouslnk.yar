rule apt_Gamaredon_GammaLoad_MaliciousLNK {
  meta:
    id             = "2612e6c6-0bda-4bfa-a840-aa0a0b4c945b"
    version        = "1.0"
    malware        = "GammaLoad"
    intrusion_set  = "Gamaredon"
    description    = "Detects Gamaredon's GammaLoad LNK"
    source         = "SEKOIA"
    creation_date  = "2022-08-01"
    classification = "TLP:WHITE"

  strings:
    $mshta = "System32\\mshta.exe"
    $trait = { 0D 0A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0D 0A }

  condition:
    uint32be(0) == 0x4c000000 and
    #trait > 100 and $mshta and
    filesize > 100KB and filesize < 400KB
}