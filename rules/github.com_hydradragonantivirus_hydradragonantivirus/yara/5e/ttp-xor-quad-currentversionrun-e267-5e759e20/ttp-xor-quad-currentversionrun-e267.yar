rule TTP_XOR_QUAD_CurrentVersionRun_e267 {
  strings:
    $key_e267 = { b1 08 [2] 95 06 [2] be 2a [2] 90 08 [2] 84 13 [2] 8b 09 [2] 95 14 [2] 97 15 [2] 8c 13 [2] 90 14 [2] 8c 3b }

  condition:
    any of them
}