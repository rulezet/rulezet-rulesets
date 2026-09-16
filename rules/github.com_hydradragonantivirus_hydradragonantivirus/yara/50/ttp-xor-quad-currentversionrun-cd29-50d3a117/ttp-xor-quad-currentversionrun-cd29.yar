rule TTP_XOR_QUAD_CurrentVersionRun_cd29 {
  strings:
    $key_cd29 = { 9e 46 [2] ba 48 [2] 91 64 [2] bf 46 [2] ab 5d [2] a4 47 [2] ba 5a [2] b8 5b [2] a3 5d [2] bf 5a [2] a3 75 }

  condition:
    any of them
}