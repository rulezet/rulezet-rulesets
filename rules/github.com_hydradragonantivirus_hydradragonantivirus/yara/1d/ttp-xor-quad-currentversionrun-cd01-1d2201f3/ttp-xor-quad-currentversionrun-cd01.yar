rule TTP_XOR_QUAD_CurrentVersionRun_cd01 {
  strings:
    $key_cd01 = { 9e 6e [2] ba 60 [2] 91 4c [2] bf 6e [2] ab 75 [2] a4 6f [2] ba 72 [2] b8 73 [2] a3 75 [2] bf 72 [2] a3 5d }

  condition:
    any of them
}