rule TTP_XOR_QUAD_CurrentVersionRun_7de0 {
  strings:
    $key_7de0 = { 2e 8f [2] 0a 81 [2] 21 ad [2] 0f 8f [2] 1b 94 [2] 14 8e [2] 0a 93 [2] 08 92 [2] 13 94 [2] 0f 93 [2] 13 bc }

  condition:
    any of them
}