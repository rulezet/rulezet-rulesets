rule TTP_XOR_QUAD_CurrentVersionRun_e204 {
  strings:
    $key_e204 = { b1 6b [2] 95 65 [2] be 49 [2] 90 6b [2] 84 70 [2] 8b 6a [2] 95 77 [2] 97 76 [2] 8c 70 [2] 90 77 [2] 8c 58 }

  condition:
    any of them
}