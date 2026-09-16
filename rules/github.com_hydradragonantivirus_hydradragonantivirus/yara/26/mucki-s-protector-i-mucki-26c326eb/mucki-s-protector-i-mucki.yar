import "pe"
rule mucki_s_protector_I____mucki {
  strings:
    $a0 = { BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8A 06 F6 D0 88 06 46 E2 F7 E9 }

  condition:
    $a0 at pe.entry_point
}