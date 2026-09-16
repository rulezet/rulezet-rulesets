rule TTP_XOR_QUAD_CurrentVersionRun_cd78 {
  strings:
    $key_cd78 = { 9e 17 [2] ba 19 [2] 91 35 [2] bf 17 [2] ab 0c [2] a4 16 [2] ba 0b [2] b8 0a [2] a3 0c [2] bf 0b [2] a3 24 }

  condition:
    any of them
}