rule TTP_XOR_QUAD_CurrentVersionRun_cd4c {
  strings:
    $key_cd4c = { 9e 23 [2] ba 2d [2] 91 01 [2] bf 23 [2] ab 38 [2] a4 22 [2] ba 3f [2] b8 3e [2] a3 38 [2] bf 3f [2] a3 10 }

  condition:
    any of them
}