rule TTP_XOR_QUAD_CurrentVersionRun_febf {
  strings:
    $key_febf = { ad d0 [2] 89 de [2] a2 f2 [2] 8c d0 [2] 98 cb [2] 97 d1 [2] 89 cc [2] 8b cd [2] 90 cb [2] 8c cc [2] 90 e3 }

  condition:
    any of them
}