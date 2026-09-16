rule TTP_XOR_QUAD_CurrentVersionRun_70b9 {
  strings:
    $key_70b9 = { 23 d6 [2] 07 d8 [2] 2c f4 [2] 02 d6 [2] 16 cd [2] 19 d7 [2] 07 ca [2] 05 cb [2] 1e cd [2] 02 ca [2] 1e e5 }

  condition:
    any of them
}