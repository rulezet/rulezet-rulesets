rule TTP_XOR_QUAD_CurrentVersionRun_cd60 {
  strings:
    $key_cd60 = { 9e 0f [2] ba 01 [2] 91 2d [2] bf 0f [2] ab 14 [2] a4 0e [2] ba 13 [2] b8 12 [2] a3 14 [2] bf 13 [2] a3 3c }

  condition:
    any of them
}