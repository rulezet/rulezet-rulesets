rule TTP_XOR_QUAD_CurrentVersionRun_cd7e {
  strings:
    $key_cd7e = { 9e 11 [2] ba 1f [2] 91 33 [2] bf 11 [2] ab 0a [2] a4 10 [2] ba 0d [2] b8 0c [2] a3 0a [2] bf 0d [2] a3 22 }

  condition:
    any of them
}