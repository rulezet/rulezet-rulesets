rule TTP_XOR_QUAD_CurrentVersionRun_f975 {
  strings:
    $key_f975 = { aa 1a [2] 8e 14 [2] a5 38 [2] 8b 1a [2] 9f 01 [2] 90 1b [2] 8e 06 [2] 8c 07 [2] 97 01 [2] 8b 06 [2] 97 29 }

  condition:
    any of them
}