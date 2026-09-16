rule TTP_XOR_QUAD_CurrentVersionRun_40f3 {
  strings:
    $key_40f3 = { 13 9c [2] 37 92 [2] 1c be [2] 32 9c [2] 26 87 [2] 29 9d [2] 37 80 [2] 35 81 [2] 2e 87 [2] 32 80 [2] 2e af }

  condition:
    any of them
}