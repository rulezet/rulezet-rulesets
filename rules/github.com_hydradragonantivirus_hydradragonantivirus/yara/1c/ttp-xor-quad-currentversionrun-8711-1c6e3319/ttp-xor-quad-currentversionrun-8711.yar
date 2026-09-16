rule TTP_XOR_QUAD_CurrentVersionRun_8711 {
  strings:
    $key_8711 = { d4 7e [2] f0 70 [2] db 5c [2] f5 7e [2] e1 65 [2] ee 7f [2] f0 62 [2] f2 63 [2] e9 65 [2] f5 62 [2] e9 4d }

  condition:
    any of them
}