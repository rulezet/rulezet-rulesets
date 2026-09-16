rule TTP_XOR_QUAD_CurrentVersionRun_6ce0 {
  strings:
    $key_6ce0 = { 3f 8f [2] 1b 81 [2] 30 ad [2] 1e 8f [2] 0a 94 [2] 05 8e [2] 1b 93 [2] 19 92 [2] 02 94 [2] 1e 93 [2] 02 bc }

  condition:
    any of them
}