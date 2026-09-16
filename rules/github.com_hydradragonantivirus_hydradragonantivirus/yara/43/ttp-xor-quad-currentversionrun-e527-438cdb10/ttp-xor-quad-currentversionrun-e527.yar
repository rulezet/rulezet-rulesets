rule TTP_XOR_QUAD_CurrentVersionRun_e527 {
  strings:
    $key_e527 = { b6 48 [2] 92 46 [2] b9 6a [2] 97 48 [2] 83 53 [2] 8c 49 [2] 92 54 [2] 90 55 [2] 8b 53 [2] 97 54 [2] 8b 7b }

  condition:
    any of them
}