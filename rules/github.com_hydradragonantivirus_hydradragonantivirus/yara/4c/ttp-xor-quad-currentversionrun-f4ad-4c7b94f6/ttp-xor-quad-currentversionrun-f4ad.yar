rule TTP_XOR_QUAD_CurrentVersionRun_f4ad {
  strings:
    $key_f4ad = { a7 c2 [2] 83 cc [2] a8 e0 [2] 86 c2 [2] 92 d9 [2] 9d c3 [2] 83 de [2] 81 df [2] 9a d9 [2] 86 de [2] 9a f1 }

  condition:
    any of them
}