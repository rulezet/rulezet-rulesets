rule TTP_XOR_QUAD_CurrentVersionRun_cd50 {
  strings:
    $key_cd50 = { 9e 3f [2] ba 31 [2] 91 1d [2] bf 3f [2] ab 24 [2] a4 3e [2] ba 23 [2] b8 22 [2] a3 24 [2] bf 23 [2] a3 0c }

  condition:
    any of them
}