rule TTP_XOR_QUAD_CurrentVersionRun_cde6 {
  strings:
    $key_cde6 = { 9e 89 [2] ba 87 [2] 91 ab [2] bf 89 [2] ab 92 [2] a4 88 [2] ba 95 [2] b8 94 [2] a3 92 [2] bf 95 [2] a3 ba }

  condition:
    any of them
}