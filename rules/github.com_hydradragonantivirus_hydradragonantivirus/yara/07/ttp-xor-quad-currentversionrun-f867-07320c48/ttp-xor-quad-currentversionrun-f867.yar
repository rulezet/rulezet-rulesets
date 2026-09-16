rule TTP_XOR_QUAD_CurrentVersionRun_f867 {
  strings:
    $key_f867 = { ab 08 [2] 8f 06 [2] a4 2a [2] 8a 08 [2] 9e 13 [2] 91 09 [2] 8f 14 [2] 8d 15 [2] 96 13 [2] 8a 14 [2] 96 3b }

  condition:
    any of them
}