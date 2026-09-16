rule TTP_XOR_QUAD_CurrentVersionRun_4002 {
  strings:
    $key_4002 = { 13 6d [2] 37 63 [2] 1c 4f [2] 32 6d [2] 26 76 [2] 29 6c [2] 37 71 [2] 35 70 [2] 2e 76 [2] 32 71 [2] 2e 5e }

  condition:
    any of them
}