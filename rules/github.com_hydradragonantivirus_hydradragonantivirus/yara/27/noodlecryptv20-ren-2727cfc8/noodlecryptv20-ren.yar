import "pe"
rule NoodleCryptv20_ren: NoodleSpa {
  meta:
    author = "_pusher_"

  strings:
    $a0 = { EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 }
    $a1 = { EB 01 9A E8 ?? 00 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 }

  condition:
    $a0 at pe.entry_point or $a1
}