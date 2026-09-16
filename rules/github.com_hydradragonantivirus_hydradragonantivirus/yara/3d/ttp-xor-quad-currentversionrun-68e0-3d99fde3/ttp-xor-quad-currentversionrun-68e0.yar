rule TTP_XOR_QUAD_CurrentVersionRun_68e0 {
  strings:
    $key_68e0 = { 3b 8f [2] 1f 81 [2] 34 ad [2] 1a 8f [2] 0e 94 [2] 01 8e [2] 1f 93 [2] 1d 92 [2] 06 94 [2] 1a 93 [2] 06 bc }

  condition:
    any of them
}