rule TTP_XOR_QUAD_CurrentVersionRun_7cf1 {
  strings:
    $key_7cf1 = { 2f 9e [2] 0b 90 [2] 20 bc [2] 0e 9e [2] 1a 85 [2] 15 9f [2] 0b 82 [2] 09 83 [2] 12 85 [2] 0e 82 [2] 12 ad }

  condition:
    any of them
}