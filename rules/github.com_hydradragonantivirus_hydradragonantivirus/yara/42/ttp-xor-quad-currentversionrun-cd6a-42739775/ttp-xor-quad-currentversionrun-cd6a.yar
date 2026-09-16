rule TTP_XOR_QUAD_CurrentVersionRun_cd6a {
  strings:
    $key_cd6a = { 9e 05 [2] ba 0b [2] 91 27 [2] bf 05 [2] ab 1e [2] a4 04 [2] ba 19 [2] b8 18 [2] a3 1e [2] bf 19 [2] a3 36 }

  condition:
    any of them
}