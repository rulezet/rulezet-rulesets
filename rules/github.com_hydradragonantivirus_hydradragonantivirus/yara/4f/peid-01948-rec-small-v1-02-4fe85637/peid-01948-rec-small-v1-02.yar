rule PEiD_01948_REC_Small_v1_02_ {
  meta:
    description = "[REC.Small v1.02]"
    ep_only     = "true"

  strings:
    $a = { 8C D8 1E E8 ?? ?? 83 ?? ?? 5D B9 ?? ?? 81 ?? ?? ?? 40 8E D8 2B DB B2 ?? ?? ?? FE C2 43 83 }

  condition:
    $a
}