import "pe"
rule Obsidium_V1_2_0_0____Obsidium_Software_____Sign_By_fly {
  strings:
    $a0 = { EB 02 ?? ?? E8 3F 1E 00 00 }

  condition:
    $a0 at pe.entry_point
}