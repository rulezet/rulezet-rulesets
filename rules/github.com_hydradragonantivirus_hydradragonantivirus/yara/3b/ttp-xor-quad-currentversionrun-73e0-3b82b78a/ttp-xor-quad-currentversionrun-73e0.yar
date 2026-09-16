rule TTP_XOR_QUAD_CurrentVersionRun_73e0 {
  strings:
    $key_73e0 = { 20 8f [2] 04 81 [2] 2f ad [2] 01 8f [2] 15 94 [2] 1a 8e [2] 04 93 [2] 06 92 [2] 1d 94 [2] 01 93 [2] 1d bc }

  condition:
    any of them
}