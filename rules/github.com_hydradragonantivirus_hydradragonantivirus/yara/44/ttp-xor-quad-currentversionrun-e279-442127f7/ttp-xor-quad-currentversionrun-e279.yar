rule TTP_XOR_QUAD_CurrentVersionRun_e279 {
  strings:
    $key_e279 = { b1 16 [2] 95 18 [2] be 34 [2] 90 16 [2] 84 0d [2] 8b 17 [2] 95 0a [2] 97 0b [2] 8c 0d [2] 90 0a [2] 8c 25 }

  condition:
    any of them
}