rule PEiD_01018_MEW_10_by_Northfox_ {
  meta:
    description = "[MEW 10 by Northfox]"
    ep_only     = "false"

  strings:
    $a = { 33 C0 E9 ?? ?? FF FF ?? 1C ?? ?? 40 }

  condition:
    $a
}