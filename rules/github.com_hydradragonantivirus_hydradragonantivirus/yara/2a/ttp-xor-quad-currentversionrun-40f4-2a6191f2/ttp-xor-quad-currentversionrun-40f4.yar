rule TTP_XOR_QUAD_CurrentVersionRun_40f4 {
  strings:
    $key_40f4 = { 13 9b [2] 37 95 [2] 1c b9 [2] 32 9b [2] 26 80 [2] 29 9a [2] 37 87 [2] 35 86 [2] 2e 80 [2] 32 87 [2] 2e a8 }

  condition:
    any of them
}