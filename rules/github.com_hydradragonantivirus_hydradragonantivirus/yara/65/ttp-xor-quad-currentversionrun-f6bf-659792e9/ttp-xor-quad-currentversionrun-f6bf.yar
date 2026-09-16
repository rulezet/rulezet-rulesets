rule TTP_XOR_QUAD_CurrentVersionRun_f6bf {
  strings:
    $key_f6bf = { a5 d0 [2] 81 de [2] aa f2 [2] 84 d0 [2] 90 cb [2] 9f d1 [2] 81 cc [2] 83 cd [2] 98 cb [2] 84 cc [2] 98 e3 }

  condition:
    any of them
}