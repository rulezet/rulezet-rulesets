rule TTP_XOR_QUAD_CurrentVersionRun_f199 {
  strings:
    $key_f199 = { a2 f6 [2] 86 f8 [2] ad d4 [2] 83 f6 [2] 97 ed [2] 98 f7 [2] 86 ea [2] 84 eb [2] 9f ed [2] 83 ea [2] 9f c5 }

  condition:
    any of them
}