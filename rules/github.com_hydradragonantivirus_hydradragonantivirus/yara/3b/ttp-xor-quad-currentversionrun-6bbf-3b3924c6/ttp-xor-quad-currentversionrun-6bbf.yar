rule TTP_XOR_QUAD_CurrentVersionRun_6bbf {
  strings:
    $key_6bbf = { 38 d0 [2] 1c de [2] 37 f2 [2] 19 d0 [2] 0d cb [2] 02 d1 [2] 1c cc [2] 1e cd [2] 05 cb [2] 19 cc [2] 05 e3 }

  condition:
    any of them
}