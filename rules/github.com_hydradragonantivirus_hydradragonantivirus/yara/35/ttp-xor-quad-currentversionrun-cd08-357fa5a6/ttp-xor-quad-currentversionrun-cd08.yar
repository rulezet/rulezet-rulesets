rule TTP_XOR_QUAD_CurrentVersionRun_cd08 {
  strings:
    $key_cd08 = { 9e 67 [2] ba 69 [2] 91 45 [2] bf 67 [2] ab 7c [2] a4 66 [2] ba 7b [2] b8 7a [2] a3 7c [2] bf 7b [2] a3 54 }

  condition:
    any of them
}