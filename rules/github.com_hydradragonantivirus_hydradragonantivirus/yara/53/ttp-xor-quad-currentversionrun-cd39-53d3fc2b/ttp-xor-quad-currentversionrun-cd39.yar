rule TTP_XOR_QUAD_CurrentVersionRun_cd39 {
  strings:
    $key_cd39 = { 9e 56 [2] ba 58 [2] 91 74 [2] bf 56 [2] ab 4d [2] a4 57 [2] ba 4a [2] b8 4b [2] a3 4d [2] bf 4a [2] a3 65 }

  condition:
    any of them
}