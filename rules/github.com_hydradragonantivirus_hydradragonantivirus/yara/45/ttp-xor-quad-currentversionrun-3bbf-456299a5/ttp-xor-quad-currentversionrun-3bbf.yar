rule TTP_XOR_QUAD_CurrentVersionRun_3bbf {
  strings:
    $key_3bbf = { 68 d0 [2] 4c de [2] 67 f2 [2] 49 d0 [2] 5d cb [2] 52 d1 [2] 4c cc [2] 4e cd [2] 55 cb [2] 49 cc [2] 55 e3 }

  condition:
    any of them
}