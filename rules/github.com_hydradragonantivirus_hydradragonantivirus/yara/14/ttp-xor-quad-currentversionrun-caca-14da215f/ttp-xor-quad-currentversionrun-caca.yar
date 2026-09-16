rule TTP_XOR_QUAD_CurrentVersionRun_caca {
  strings:
    $key_caca = { 99 a5 [2] bd ab [2] 96 87 [2] b8 a5 [2] ac be [2] a3 a4 [2] bd b9 [2] bf b8 [2] a4 be [2] b8 b9 [2] a4 96 }

  condition:
    any of them
}