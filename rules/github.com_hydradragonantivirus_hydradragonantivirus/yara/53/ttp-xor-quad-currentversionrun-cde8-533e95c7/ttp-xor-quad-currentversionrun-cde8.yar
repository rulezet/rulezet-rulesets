rule TTP_XOR_QUAD_CurrentVersionRun_cde8 {
  strings:
    $key_cde8 = { 9e 87 [2] ba 89 [2] 91 a5 [2] bf 87 [2] ab 9c [2] a4 86 [2] ba 9b [2] b8 9a [2] a3 9c [2] bf 9b [2] a3 b4 }

  condition:
    any of them
}