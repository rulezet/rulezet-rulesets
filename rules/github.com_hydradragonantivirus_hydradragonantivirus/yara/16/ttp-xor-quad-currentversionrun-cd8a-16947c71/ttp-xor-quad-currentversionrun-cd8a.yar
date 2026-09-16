rule TTP_XOR_QUAD_CurrentVersionRun_cd8a {
  strings:
    $key_cd8a = { 9e e5 [2] ba eb [2] 91 c7 [2] bf e5 [2] ab fe [2] a4 e4 [2] ba f9 [2] b8 f8 [2] a3 fe [2] bf f9 [2] a3 d6 }

  condition:
    any of them
}