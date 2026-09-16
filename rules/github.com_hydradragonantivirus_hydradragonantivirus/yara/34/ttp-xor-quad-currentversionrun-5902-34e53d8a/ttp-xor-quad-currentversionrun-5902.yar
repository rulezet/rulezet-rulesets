rule TTP_XOR_QUAD_CurrentVersionRun_5902 {
  strings:
    $key_5902 = { 0a 6d [2] 2e 63 [2] 05 4f [2] 2b 6d [2] 3f 76 [2] 30 6c [2] 2e 71 [2] 2c 70 [2] 37 76 [2] 2b 71 [2] 37 5e }

  condition:
    any of them
}