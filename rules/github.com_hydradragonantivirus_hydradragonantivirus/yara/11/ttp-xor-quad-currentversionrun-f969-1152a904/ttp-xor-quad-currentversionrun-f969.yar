rule TTP_XOR_QUAD_CurrentVersionRun_f969 {
  strings:
    $key_f969 = { aa 06 [2] 8e 08 [2] a5 24 [2] 8b 06 [2] 9f 1d [2] 90 07 [2] 8e 1a [2] 8c 1b [2] 97 1d [2] 8b 1a [2] 97 35 }

  condition:
    any of them
}