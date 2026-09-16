rule TTP_XOR_QUAD_CurrentVersionRun_6ebf {
  strings:
    $key_6ebf = { 3d d0 [2] 19 de [2] 32 f2 [2] 1c d0 [2] 08 cb [2] 07 d1 [2] 19 cc [2] 1b cd [2] 00 cb [2] 1c cc [2] 00 e3 }

  condition:
    any of them
}