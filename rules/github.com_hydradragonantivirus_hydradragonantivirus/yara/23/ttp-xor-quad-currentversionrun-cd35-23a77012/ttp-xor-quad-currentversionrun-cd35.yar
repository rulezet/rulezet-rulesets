rule TTP_XOR_QUAD_CurrentVersionRun_cd35 {
  strings:
    $key_cd35 = { 9e 5a [2] ba 54 [2] 91 78 [2] bf 5a [2] ab 41 [2] a4 5b [2] ba 46 [2] b8 47 [2] a3 41 [2] bf 46 [2] a3 69 }

  condition:
    any of them
}