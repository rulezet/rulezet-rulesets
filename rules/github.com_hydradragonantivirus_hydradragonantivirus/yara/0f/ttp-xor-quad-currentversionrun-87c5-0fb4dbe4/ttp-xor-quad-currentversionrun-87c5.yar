rule TTP_XOR_QUAD_CurrentVersionRun_87c5 {
  strings:
    $key_87c5 = { d4 aa [2] f0 a4 [2] db 88 [2] f5 aa [2] e1 b1 [2] ee ab [2] f0 b6 [2] f2 b7 [2] e9 b1 [2] f5 b6 [2] e9 99 }

  condition:
    any of them
}