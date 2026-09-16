rule TTP_XOR_QUAD_CurrentVersionRun_e667 {
  strings:
    $key_e667 = { b5 08 [2] 91 06 [2] ba 2a [2] 94 08 [2] 80 13 [2] 8f 09 [2] 91 14 [2] 93 15 [2] 88 13 [2] 94 14 [2] 88 3b }

  condition:
    any of them
}