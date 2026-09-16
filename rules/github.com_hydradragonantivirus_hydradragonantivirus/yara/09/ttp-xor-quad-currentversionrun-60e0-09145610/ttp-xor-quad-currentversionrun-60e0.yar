rule TTP_XOR_QUAD_CurrentVersionRun_60e0 {
  strings:
    $key_60e0 = { 33 8f [2] 17 81 [2] 3c ad [2] 12 8f [2] 06 94 [2] 09 8e [2] 17 93 [2] 15 92 [2] 0e 94 [2] 12 93 [2] 0e bc }

  condition:
    any of them
}