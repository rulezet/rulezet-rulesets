rule TTP_XOR_QUAD_CurrentVersionRun_1cf1 {
  strings:
    $key_1cf1 = { 4f 9e [2] 6b 90 [2] 40 bc [2] 6e 9e [2] 7a 85 [2] 75 9f [2] 6b 82 [2] 69 83 [2] 72 85 [2] 6e 82 [2] 72 ad }

  condition:
    any of them
}