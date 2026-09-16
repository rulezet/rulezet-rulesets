rule TTP_XOR_QUAD_CurrentVersionRun_cd6b {
  strings:
    $key_cd6b = { 9e 04 [2] ba 0a [2] 91 26 [2] bf 04 [2] ab 1f [2] a4 05 [2] ba 18 [2] b8 19 [2] a3 1f [2] bf 18 [2] a3 37 }

  condition:
    any of them
}