rule TTP_XOR_QUAD_CurrentVersionRun_e25b {
  strings:
    $key_e25b = { b1 34 [2] 95 3a [2] be 16 [2] 90 34 [2] 84 2f [2] 8b 35 [2] 95 28 [2] 97 29 [2] 8c 2f [2] 90 28 [2] 8c 07 }

  condition:
    any of them
}