rule TTP_XOR_QUAD_CurrentVersionRun_ca99 {
  strings:
    $key_ca99 = { 99 f6 [2] bd f8 [2] 96 d4 [2] b8 f6 [2] ac ed [2] a3 f7 [2] bd ea [2] bf eb [2] a4 ed [2] b8 ea [2] a4 c5 }

  condition:
    any of them
}