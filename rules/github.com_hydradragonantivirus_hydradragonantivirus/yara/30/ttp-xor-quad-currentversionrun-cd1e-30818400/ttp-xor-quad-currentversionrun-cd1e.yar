rule TTP_XOR_QUAD_CurrentVersionRun_cd1e {
  strings:
    $key_cd1e = { 9e 71 [2] ba 7f [2] 91 53 [2] bf 71 [2] ab 6a [2] a4 70 [2] ba 6d [2] b8 6c [2] a3 6a [2] bf 6d [2] a3 42 }

  condition:
    any of them
}