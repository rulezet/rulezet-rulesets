rule TTP_XOR_QUAD_CurrentVersionRun_fbbf {
  strings:
    $key_fbbf = { a8 d0 [2] 8c de [2] a7 f2 [2] 89 d0 [2] 9d cb [2] 92 d1 [2] 8c cc [2] 8e cd [2] 95 cb [2] 89 cc [2] 95 e3 }

  condition:
    any of them
}