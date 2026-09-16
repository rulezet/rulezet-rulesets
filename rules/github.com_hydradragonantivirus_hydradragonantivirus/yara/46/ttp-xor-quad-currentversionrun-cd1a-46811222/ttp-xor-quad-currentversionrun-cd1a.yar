rule TTP_XOR_QUAD_CurrentVersionRun_cd1a {
  strings:
    $key_cd1a = { 9e 75 [2] ba 7b [2] 91 57 [2] bf 75 [2] ab 6e [2] a4 74 [2] ba 69 [2] b8 68 [2] a3 6e [2] bf 69 [2] a3 46 }

  condition:
    any of them
}