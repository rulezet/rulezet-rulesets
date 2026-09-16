rule TTP_XOR_QUAD_CurrentVersionRun_eebf {
  strings:
    $key_eebf = { bd d0 [2] 99 de [2] b2 f2 [2] 9c d0 [2] 88 cb [2] 87 d1 [2] 99 cc [2] 9b cd [2] 80 cb [2] 9c cc [2] 80 e3 }

  condition:
    any of them
}