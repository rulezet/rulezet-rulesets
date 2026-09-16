rule TTP_XOR_QUAD_CurrentVersionRun_cd05 {
  strings:
    $key_cd05 = { 9e 6a [2] ba 64 [2] 91 48 [2] bf 6a [2] ab 71 [2] a4 6b [2] ba 76 [2] b8 77 [2] a3 71 [2] bf 76 [2] a3 59 }

  condition:
    any of them
}