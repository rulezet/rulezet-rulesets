rule TTP_XOR_QUAD_CurrentVersionRun_e206 {
  strings:
    $key_e206 = { b1 69 [2] 95 67 [2] be 4b [2] 90 69 [2] 84 72 [2] 8b 68 [2] 95 75 [2] 97 74 [2] 8c 72 [2] 90 75 [2] 8c 5a }

  condition:
    any of them
}