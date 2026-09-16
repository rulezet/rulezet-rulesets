rule TTP_XOR_QUAD_CurrentVersionRun_e244 {
  strings:
    $key_e244 = { b1 2b [2] 95 25 [2] be 09 [2] 90 2b [2] 84 30 [2] 8b 2a [2] 95 37 [2] 97 36 [2] 8c 30 [2] 90 37 [2] 8c 18 }

  condition:
    any of them
}