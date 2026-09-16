rule Mimikatz_SampleSet_4: APT {
  meta:
    description = "Mimikatz Rule generated from a big Mimikatz sample set"
    author      = "Florian Roth - Florian Roth"
    hash1       = "8991aeef8b33049c5997c59afcea4a27"
    hash2       = "a3e00b039f2d2ea04a4274506dd83be0"
    hash3       = "cb5d40cc8db79c3d24f20f443f7e5926"
    score       = 40

  strings:
    $s0 = "notsupported" fullword
    $s1 = "getLiveSSP" fullword
    $s2 = "getKerberos" fullword
    $s3 = "getLiveSSPFunctions" fullword
    $s4 = "getKerberosFunctions" fullword
    $s5 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><tr"
    $s6 = "getCredmanFunctions" fullword
    $s7 = "getCredman" fullword
    $s8 = "find_tokens" fullword

  condition:
    all of them
}