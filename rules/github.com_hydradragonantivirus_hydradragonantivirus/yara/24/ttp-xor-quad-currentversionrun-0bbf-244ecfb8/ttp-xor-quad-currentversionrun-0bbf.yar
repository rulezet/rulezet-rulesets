rule TTP_XOR_QUAD_CurrentVersionRun_0bbf {
  strings:
    $key_0bbf = { 58 d0 [2] 7c de [2] 57 f2 [2] 79 d0 [2] 6d cb [2] 62 d1 [2] 7c cc [2] 7e cd [2] 65 cb [2] 79 cc [2] 65 e3 }

  condition:
    any of them
}