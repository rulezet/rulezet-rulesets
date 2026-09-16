rule TTP_XOR_QUAD_CurrentVersionRun_e27b {
  strings:
    $key_e27b = { b1 14 [2] 95 1a [2] be 36 [2] 90 14 [2] 84 0f [2] 8b 15 [2] 95 08 [2] 97 09 [2] 8c 0f [2] 90 08 [2] 8c 27 }

  condition:
    any of them
}