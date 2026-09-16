rule PEiD_02070_Shrink_Wrap_v1_4_ {
  meta:
    description = "[Shrink Wrap v1.4]"
    ep_only     = "true"

  strings:
    $a = { 58 60 8B E8 55 33 F6 68 48 01 ?? ?? E8 49 01 ?? ?? EB }

  condition:
    $a
}