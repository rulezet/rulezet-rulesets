import "pe"
rule PEiD_00354_Borland_Pascal_v7_0_Protected_Mode_ {
  meta:
    description = "[Borland Pascal v7.0 Protected Mode]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? BB ?? ?? 8E D0 8B E3 8C D8 8E C0 0E 1F A1 ?? ?? 25 ?? ?? A3 ?? ?? E8 ?? ?? 83 3E ?? ?? ?? 75 }

  condition:
    $a at pe.entry_point
}