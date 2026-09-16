rule TTP_XOR_QUAD_CurrentVersionRun_1587 {
  strings:
    $key_1587 = { 46 e8 [2] 62 e6 [2] 49 ca [2] 67 e8 [2] 73 f3 [2] 7c e9 [2] 62 f4 [2] 60 f5 [2] 7b f3 [2] 67 f4 [2] 7b db }

  condition:
    any of them
}