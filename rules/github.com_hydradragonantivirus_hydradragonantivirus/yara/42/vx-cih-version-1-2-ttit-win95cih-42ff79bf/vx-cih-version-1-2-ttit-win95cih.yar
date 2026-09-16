import "pe"
rule Vx__CIH_Version_1_2_TTIT____WIN95CIH___ {
  strings:
    $a0 = { 55 8D ?? ?? ?? 33 DB 64 87 03 E8 ?? ?? ?? ?? 5B 8D }

  condition:
    $a0 at pe.entry_point
}