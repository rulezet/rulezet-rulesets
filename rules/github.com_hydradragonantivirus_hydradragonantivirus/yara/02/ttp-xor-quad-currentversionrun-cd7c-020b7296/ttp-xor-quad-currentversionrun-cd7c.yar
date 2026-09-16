rule TTP_XOR_QUAD_CurrentVersionRun_cd7c {
  strings:
    $key_cd7c = { 9e 13 [2] ba 1d [2] 91 31 [2] bf 13 [2] ab 08 [2] a4 12 [2] ba 0f [2] b8 0e [2] a3 08 [2] bf 0f [2] a3 20 }

  condition:
    any of them
}