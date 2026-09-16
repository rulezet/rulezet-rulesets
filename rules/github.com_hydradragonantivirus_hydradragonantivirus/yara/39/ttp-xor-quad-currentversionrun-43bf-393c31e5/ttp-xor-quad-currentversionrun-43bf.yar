rule TTP_XOR_QUAD_CurrentVersionRun_43bf {
  strings:
    $key_43bf = { 10 d0 [2] 34 de [2] 1f f2 [2] 31 d0 [2] 25 cb [2] 2a d1 [2] 34 cc [2] 36 cd [2] 2d cb [2] 31 cc [2] 2d e3 }

  condition:
    any of them
}