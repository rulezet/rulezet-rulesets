rule TTP_XOR_QUAD_CurrentVersionRun_43aa {
  strings:
    $key_43aa = { 10 c5 [2] 34 cb [2] 1f e7 [2] 31 c5 [2] 25 de [2] 2a c4 [2] 34 d9 [2] 36 d8 [2] 2d de [2] 31 d9 [2] 2d f6 }

  condition:
    any of them
}