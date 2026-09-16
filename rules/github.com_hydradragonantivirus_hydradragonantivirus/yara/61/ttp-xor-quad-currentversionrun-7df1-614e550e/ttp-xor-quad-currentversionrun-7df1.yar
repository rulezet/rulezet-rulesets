rule TTP_XOR_QUAD_CurrentVersionRun_7df1 {
  strings:
    $key_7df1 = { 2e 9e [2] 0a 90 [2] 21 bc [2] 0f 9e [2] 1b 85 [2] 14 9f [2] 0a 82 [2] 08 83 [2] 13 85 [2] 0f 82 [2] 13 ad }

  condition:
    any of them
}