rule TTP_XOR_QUAD_CurrentVersionRun_0787 {
  strings:
    $key_0787 = { 54 e8 [2] 70 e6 [2] 5b ca [2] 75 e8 [2] 61 f3 [2] 6e e9 [2] 70 f4 [2] 72 f5 [2] 69 f3 [2] 75 f4 [2] 69 db }

  condition:
    any of them
}