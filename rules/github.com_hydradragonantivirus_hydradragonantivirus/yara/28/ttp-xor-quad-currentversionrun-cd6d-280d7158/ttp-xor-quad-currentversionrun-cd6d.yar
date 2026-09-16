rule TTP_XOR_QUAD_CurrentVersionRun_cd6d {
  strings:
    $key_cd6d = { 9e 02 [2] ba 0c [2] 91 20 [2] bf 02 [2] ab 19 [2] a4 03 [2] ba 1e [2] b8 1f [2] a3 19 [2] bf 1e [2] a3 31 }

  condition:
    any of them
}