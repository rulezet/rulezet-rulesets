rule TTP_XOR_QUAD_CurrentVersionRun_cd28 {
  strings:
    $key_cd28 = { 9e 47 [2] ba 49 [2] 91 65 [2] bf 47 [2] ab 5c [2] a4 46 [2] ba 5b [2] b8 5a [2] a3 5c [2] bf 5b [2] a3 74 }

  condition:
    any of them
}