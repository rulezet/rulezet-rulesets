rule TTP_XOR_QUAD_CurrentVersionRun_5787 {
  strings:
    $key_5787 = { 04 e8 [2] 20 e6 [2] 0b ca [2] 25 e8 [2] 31 f3 [2] 3e e9 [2] 20 f4 [2] 22 f5 [2] 39 f3 [2] 25 f4 [2] 39 db }

  condition:
    any of them
}