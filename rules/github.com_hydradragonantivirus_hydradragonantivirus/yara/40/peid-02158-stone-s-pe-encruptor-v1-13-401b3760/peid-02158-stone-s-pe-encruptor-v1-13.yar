rule PEiD_02158_Stone_s_PE_Encruptor_v1_13_ {
  meta:
    description = "[Stone`s PE Encruptor v1.13]"
    ep_only     = "true"

  strings:
    $a = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 }

  condition:
    $a
}