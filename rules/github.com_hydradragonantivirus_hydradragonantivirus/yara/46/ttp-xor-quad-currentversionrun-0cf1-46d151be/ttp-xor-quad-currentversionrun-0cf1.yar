rule TTP_XOR_QUAD_CurrentVersionRun_0cf1 {
  strings:
    $key_0cf1 = { 5f 9e [2] 7b 90 [2] 50 bc [2] 7e 9e [2] 6a 85 [2] 65 9f [2] 7b 82 [2] 79 83 [2] 62 85 [2] 7e 82 [2] 62 ad }

  condition:
    any of them
}