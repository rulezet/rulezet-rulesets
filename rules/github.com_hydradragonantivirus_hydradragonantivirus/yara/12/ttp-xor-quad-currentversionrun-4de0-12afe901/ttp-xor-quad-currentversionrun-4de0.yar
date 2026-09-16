rule TTP_XOR_QUAD_CurrentVersionRun_4de0 {
  strings:
    $key_4de0 = { 1e 8f [2] 3a 81 [2] 11 ad [2] 3f 8f [2] 2b 94 [2] 24 8e [2] 3a 93 [2] 38 92 [2] 23 94 [2] 3f 93 [2] 23 bc }

  condition:
    any of them
}