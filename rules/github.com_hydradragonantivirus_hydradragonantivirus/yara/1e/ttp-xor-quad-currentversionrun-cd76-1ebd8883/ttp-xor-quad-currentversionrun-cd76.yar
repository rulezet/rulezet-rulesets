rule TTP_XOR_QUAD_CurrentVersionRun_cd76 {
  strings:
    $key_cd76 = { 9e 19 [2] ba 17 [2] 91 3b [2] bf 19 [2] ab 02 [2] a4 18 [2] ba 05 [2] b8 04 [2] a3 02 [2] bf 05 [2] a3 2a }

  condition:
    any of them
}