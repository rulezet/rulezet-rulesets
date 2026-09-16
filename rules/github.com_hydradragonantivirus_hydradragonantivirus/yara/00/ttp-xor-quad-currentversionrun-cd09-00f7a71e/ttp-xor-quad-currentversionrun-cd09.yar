rule TTP_XOR_QUAD_CurrentVersionRun_cd09 {
  strings:
    $key_cd09 = { 9e 66 [2] ba 68 [2] 91 44 [2] bf 66 [2] ab 7d [2] a4 67 [2] ba 7a [2] b8 7b [2] a3 7d [2] bf 7a [2] a3 55 }

  condition:
    any of them
}