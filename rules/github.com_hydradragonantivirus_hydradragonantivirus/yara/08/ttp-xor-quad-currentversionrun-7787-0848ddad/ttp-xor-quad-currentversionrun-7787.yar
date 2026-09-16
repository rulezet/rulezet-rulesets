rule TTP_XOR_QUAD_CurrentVersionRun_7787 {
  strings:
    $key_7787 = { 24 e8 [2] 00 e6 [2] 2b ca [2] 05 e8 [2] 11 f3 [2] 1e e9 [2] 00 f4 [2] 02 f5 [2] 19 f3 [2] 05 f4 [2] 19 db }

  condition:
    any of them
}