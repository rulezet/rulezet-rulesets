rule TTP_XOR_QUAD_CurrentVersionRun_cd34 {
  strings:
    $key_cd34 = { 9e 5b [2] ba 55 [2] 91 79 [2] bf 5b [2] ab 40 [2] a4 5a [2] ba 47 [2] b8 46 [2] a3 40 [2] bf 47 [2] a3 68 }

  condition:
    any of them
}