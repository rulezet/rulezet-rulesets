rule TTP_XOR_QUAD_CurrentVersionRun_e65b {
  strings:
    $key_e65b = { b5 34 [2] 91 3a [2] ba 16 [2] 94 34 [2] 80 2f [2] 8f 35 [2] 91 28 [2] 93 29 [2] 88 2f [2] 94 28 [2] 88 07 }

  condition:
    any of them
}