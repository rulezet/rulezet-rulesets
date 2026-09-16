rule TTP_XOR_QUAD_CurrentVersionRun_e3a6 {
  strings:
    $key_e3a6 = { b0 c9 [2] 94 c7 [2] bf eb [2] 91 c9 [2] 85 d2 [2] 8a c8 [2] 94 d5 [2] 96 d4 [2] 8d d2 [2] 91 d5 [2] 8d fa }

  condition:
    any of them
}