rule TTP_XOR_QUAD_CurrentVersionRun_1ebf {
  strings:
    $key_1ebf = { 4d d0 [2] 69 de [2] 42 f2 [2] 6c d0 [2] 78 cb [2] 77 d1 [2] 69 cc [2] 6b cd [2] 70 cb [2] 6c cc [2] 70 e3 }

  condition:
    any of them
}