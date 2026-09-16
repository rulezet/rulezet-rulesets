rule TTP_XOR_QUAD_CurrentVersionRun_8717 {
  strings:
    $key_8717 = { d4 78 [2] f0 76 [2] db 5a [2] f5 78 [2] e1 63 [2] ee 79 [2] f0 64 [2] f2 65 [2] e9 63 [2] f5 64 [2] e9 4b }

  condition:
    any of them
}