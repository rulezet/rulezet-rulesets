rule TTP_XOR_QUAD_CurrentVersionRun_cd4a {
  strings:
    $key_cd4a = { 9e 25 [2] ba 2b [2] 91 07 [2] bf 25 [2] ab 3e [2] a4 24 [2] ba 39 [2] b8 38 [2] a3 3e [2] bf 39 [2] a3 16 }

  condition:
    any of them
}