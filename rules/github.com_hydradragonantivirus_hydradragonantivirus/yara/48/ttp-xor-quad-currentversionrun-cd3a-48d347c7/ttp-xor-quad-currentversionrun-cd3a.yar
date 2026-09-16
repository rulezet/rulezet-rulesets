rule TTP_XOR_QUAD_CurrentVersionRun_cd3a {
  strings:
    $key_cd3a = { 9e 55 [2] ba 5b [2] 91 77 [2] bf 55 [2] ab 4e [2] a4 54 [2] ba 49 [2] b8 48 [2] a3 4e [2] bf 49 [2] a3 66 }

  condition:
    any of them
}