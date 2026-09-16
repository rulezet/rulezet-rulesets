rule TTP_XOR_QUAD_CurrentVersionRun_f7bf {
  strings:
    $key_f7bf = { a4 d0 [2] 80 de [2] ab f2 [2] 85 d0 [2] 91 cb [2] 9e d1 [2] 80 cc [2] 82 cd [2] 99 cb [2] 85 cc [2] 99 e3 }

  condition:
    any of them
}