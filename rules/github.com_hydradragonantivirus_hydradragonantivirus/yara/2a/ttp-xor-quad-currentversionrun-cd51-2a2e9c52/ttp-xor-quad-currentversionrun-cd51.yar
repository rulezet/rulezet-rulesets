rule TTP_XOR_QUAD_CurrentVersionRun_cd51 {
  strings:
    $key_cd51 = { 9e 3e [2] ba 30 [2] 91 1c [2] bf 3e [2] ab 25 [2] a4 3f [2] ba 22 [2] b8 23 [2] a3 25 [2] bf 22 [2] a3 0d }

  condition:
    any of them
}