rule TTP_XOR_QUAD_CurrentVersionRun_87c4 {
  strings:
    $key_87c4 = { d4 ab [2] f0 a5 [2] db 89 [2] f5 ab [2] e1 b0 [2] ee aa [2] f0 b7 [2] f2 b6 [2] e9 b0 [2] f5 b7 [2] e9 98 }

  condition:
    any of them
}