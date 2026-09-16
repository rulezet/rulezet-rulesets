rule TTP_XOR_QUAD_CurrentVersionRun_cd7a {
  strings:
    $key_cd7a = { 9e 15 [2] ba 1b [2] 91 37 [2] bf 15 [2] ab 0e [2] a4 14 [2] ba 09 [2] b8 08 [2] a3 0e [2] bf 09 [2] a3 26 }

  condition:
    any of them
}