rule TTP_XOR_QUAD_CurrentVersionRun_cd2c {
  strings:
    $key_cd2c = { 9e 43 [2] ba 4d [2] 91 61 [2] bf 43 [2] ab 58 [2] a4 42 [2] ba 5f [2] b8 5e [2] a3 58 [2] bf 5f [2] a3 70 }

  condition:
    any of them
}