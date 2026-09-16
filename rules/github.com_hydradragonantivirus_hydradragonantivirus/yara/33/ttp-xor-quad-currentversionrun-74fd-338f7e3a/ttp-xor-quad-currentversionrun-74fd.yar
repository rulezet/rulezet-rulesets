rule TTP_XOR_QUAD_CurrentVersionRun_74fd {
  strings:
    $key_74fd = { 27 92 [2] 03 9c [2] 28 b0 [2] 06 92 [2] 12 89 [2] 1d 93 [2] 03 8e [2] 01 8f [2] 1a 89 [2] 06 8e [2] 1a a1 }

  condition:
    any of them
}