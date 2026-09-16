import "pe"
rule PEiD_02280_TMT_Pascal_v0_40_ {
  meta:
    description = "[TMT-Pascal v0.40]"
    ep_only     = "true"

  strings:
    $a = { 0E 1F 06 8C 06 ?? ?? 26 A1 ?? ?? A3 ?? ?? 8E C0 66 33 FF 66 33 C9 }

  condition:
    $a at pe.entry_point
}