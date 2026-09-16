rule TTP_XOR_QUAD_CurrentVersionRun_e384 {
  strings:
    $key_e384 = { b0 eb [2] 94 e5 [2] bf c9 [2] 91 eb [2] 85 f0 [2] 8a ea [2] 94 f7 [2] 96 f6 [2] 8d f0 [2] 91 f7 [2] 8d d8 }

  condition:
    any of them
}