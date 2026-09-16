import "pe"
rule Thinstall_vx_x {
  strings:
    $a0 = { B8 EF BE AD DE 50 6A ?? FF 15 10 19 40 ?? E9 AD FF FF FF }

  condition:
    $a0 at pe.entry_point
}