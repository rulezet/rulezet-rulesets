rule TTP_XOR_QUAD_CurrentVersionRun_cd8c {
  strings:
    $key_cd8c = { 9e e3 [2] ba ed [2] 91 c1 [2] bf e3 [2] ab f8 [2] a4 e2 [2] ba ff [2] b8 fe [2] a3 f8 [2] bf ff [2] a3 d0 }

  condition:
    any of them
}