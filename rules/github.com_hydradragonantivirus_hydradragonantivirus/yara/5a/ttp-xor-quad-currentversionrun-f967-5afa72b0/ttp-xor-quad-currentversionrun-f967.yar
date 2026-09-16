rule TTP_XOR_QUAD_CurrentVersionRun_f967 {
  strings:
    $key_f967 = { aa 08 [2] 8e 06 [2] a5 2a [2] 8b 08 [2] 9f 13 [2] 90 09 [2] 8e 14 [2] 8c 15 [2] 97 13 [2] 8b 14 [2] 97 3b }

  condition:
    any of them
}