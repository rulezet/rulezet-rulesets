rule TTP_XOR_QUAD_CurrentVersionRun_f7ad {
  strings:
    $key_f7ad = { a4 c2 [2] 80 cc [2] ab e0 [2] 85 c2 [2] 91 d9 [2] 9e c3 [2] 80 de [2] 82 df [2] 99 d9 [2] 85 de [2] 99 f1 }

  condition:
    any of them
}