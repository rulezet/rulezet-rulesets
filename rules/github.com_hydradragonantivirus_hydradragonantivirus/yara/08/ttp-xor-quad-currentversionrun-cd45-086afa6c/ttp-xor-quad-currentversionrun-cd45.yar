rule TTP_XOR_QUAD_CurrentVersionRun_cd45 {
  strings:
    $key_cd45 = { 9e 2a [2] ba 24 [2] 91 08 [2] bf 2a [2] ab 31 [2] a4 2b [2] ba 36 [2] b8 37 [2] a3 31 [2] bf 36 [2] a3 19 }

  condition:
    any of them
}