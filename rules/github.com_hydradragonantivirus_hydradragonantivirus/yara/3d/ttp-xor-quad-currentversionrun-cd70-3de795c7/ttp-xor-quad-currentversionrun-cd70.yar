rule TTP_XOR_QUAD_CurrentVersionRun_cd70 {
  strings:
    $key_cd70 = { 9e 1f [2] ba 11 [2] 91 3d [2] bf 1f [2] ab 04 [2] a4 1e [2] ba 03 [2] b8 02 [2] a3 04 [2] bf 03 [2] a3 2c }

  condition:
    any of them
}