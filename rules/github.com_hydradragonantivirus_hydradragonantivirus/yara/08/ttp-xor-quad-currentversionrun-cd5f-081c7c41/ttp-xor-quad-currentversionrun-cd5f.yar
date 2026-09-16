rule TTP_XOR_QUAD_CurrentVersionRun_cd5f {
  strings:
    $key_cd5f = { 9e 30 [2] ba 3e [2] 91 12 [2] bf 30 [2] ab 2b [2] a4 31 [2] ba 2c [2] b8 2d [2] a3 2b [2] bf 2c [2] a3 03 }

  condition:
    any of them
}