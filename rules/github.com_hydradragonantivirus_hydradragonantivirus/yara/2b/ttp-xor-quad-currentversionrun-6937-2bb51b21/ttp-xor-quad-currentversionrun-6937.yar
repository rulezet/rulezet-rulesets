rule TTP_XOR_QUAD_CurrentVersionRun_6937 {
  strings:
    $key_6937 = { 3a 58 [2] 1e 56 [2] 35 7a [2] 1b 58 [2] 0f 43 [2] 00 59 [2] 1e 44 [2] 1c 45 [2] 07 43 [2] 1b 44 [2] 07 6b }

  condition:
    any of them
}