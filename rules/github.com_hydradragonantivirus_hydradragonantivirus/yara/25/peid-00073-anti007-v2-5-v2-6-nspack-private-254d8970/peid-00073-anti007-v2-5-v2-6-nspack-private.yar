rule PEiD_00073_Anti007_V2_5_V2_6____NsPacK_Private_ {
  meta:
    description = "[Anti007 V2.5-V2.6 -> NsPacK Private]"
    ep_only     = "true"

  strings:
    $a = { 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 53 }

  condition:
    $a
}