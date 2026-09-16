rule TTP_XOR_QUAD_CurrentVersionRun_cd2f {
  strings:
    $key_cd2f = { 9e 40 [2] ba 4e [2] 91 62 [2] bf 40 [2] ab 5b [2] a4 41 [2] ba 5c [2] b8 5d [2] a3 5b [2] bf 5c [2] a3 73 }

  condition:
    any of them
}