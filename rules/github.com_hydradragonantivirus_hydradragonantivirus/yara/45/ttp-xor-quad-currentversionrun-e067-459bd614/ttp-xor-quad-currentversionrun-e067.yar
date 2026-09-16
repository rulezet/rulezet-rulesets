rule TTP_XOR_QUAD_CurrentVersionRun_e067 {
  strings:
    $key_e067 = { b3 08 [2] 97 06 [2] bc 2a [2] 92 08 [2] 86 13 [2] 89 09 [2] 97 14 [2] 95 15 [2] 8e 13 [2] 92 14 [2] 8e 3b }

  condition:
    any of them
}