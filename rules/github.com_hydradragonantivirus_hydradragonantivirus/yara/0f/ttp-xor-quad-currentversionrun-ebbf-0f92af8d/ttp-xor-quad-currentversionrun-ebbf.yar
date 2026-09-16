rule TTP_XOR_QUAD_CurrentVersionRun_ebbf {
  strings:
    $key_ebbf = { b8 d0 [2] 9c de [2] b7 f2 [2] 99 d0 [2] 8d cb [2] 82 d1 [2] 9c cc [2] 9e cd [2] 85 cb [2] 99 cc [2] 85 e3 }

  condition:
    any of them
}