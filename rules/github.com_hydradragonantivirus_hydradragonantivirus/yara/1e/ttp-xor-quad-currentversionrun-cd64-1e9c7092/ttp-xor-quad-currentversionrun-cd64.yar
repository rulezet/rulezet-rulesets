rule TTP_XOR_QUAD_CurrentVersionRun_cd64 {
  strings:
    $key_cd64 = { 9e 0b [2] ba 05 [2] 91 29 [2] bf 0b [2] ab 10 [2] a4 0a [2] ba 17 [2] b8 16 [2] a3 10 [2] bf 17 [2] a3 38 }

  condition:
    any of them
}