rule TTP_XOR_QUAD_CurrentVersionRun_f85b {
  strings:
    $key_f85b = { ab 34 [2] 8f 3a [2] a4 16 [2] 8a 34 [2] 9e 2f [2] 91 35 [2] 8f 28 [2] 8d 29 [2] 96 2f [2] 8a 28 [2] 96 07 }

  condition:
    any of them
}