rule TTP_XOR_QUAD_CurrentVersionRun_1199 {
  strings:
    $key_1199 = { 42 f6 [2] 66 f8 [2] 4d d4 [2] 63 f6 [2] 77 ed [2] 78 f7 [2] 66 ea [2] 64 eb [2] 7f ed [2] 63 ea [2] 7f c5 }

  condition:
    any of them
}