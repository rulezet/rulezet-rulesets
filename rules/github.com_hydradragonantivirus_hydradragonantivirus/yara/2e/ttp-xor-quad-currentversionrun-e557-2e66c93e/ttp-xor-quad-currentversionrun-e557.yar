rule TTP_XOR_QUAD_CurrentVersionRun_e557 {
  strings:
    $key_e557 = { b6 38 [2] 92 36 [2] b9 1a [2] 97 38 [2] 83 23 [2] 8c 39 [2] 92 24 [2] 90 25 [2] 8b 23 [2] 97 24 [2] 8b 0b }

  condition:
    any of them
}