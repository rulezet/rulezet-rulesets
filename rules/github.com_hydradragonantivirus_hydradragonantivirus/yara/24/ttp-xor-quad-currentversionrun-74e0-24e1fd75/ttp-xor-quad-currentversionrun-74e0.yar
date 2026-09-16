rule TTP_XOR_QUAD_CurrentVersionRun_74e0 {
  strings:
    $key_74e0 = { 27 8f [2] 03 81 [2] 28 ad [2] 06 8f [2] 12 94 [2] 1d 8e [2] 03 93 [2] 01 92 [2] 1a 94 [2] 06 93 [2] 1a bc }

  condition:
    any of them
}