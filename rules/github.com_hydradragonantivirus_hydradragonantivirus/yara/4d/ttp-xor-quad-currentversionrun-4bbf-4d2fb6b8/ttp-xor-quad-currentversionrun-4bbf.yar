rule TTP_XOR_QUAD_CurrentVersionRun_4bbf {
  strings:
    $key_4bbf = { 18 d0 [2] 3c de [2] 17 f2 [2] 39 d0 [2] 2d cb [2] 22 d1 [2] 3c cc [2] 3e cd [2] 25 cb [2] 39 cc [2] 25 e3 }

  condition:
    any of them
}