rule TTP_XOR_QUAD_CurrentVersionRun_1841 {
  strings:
    $key_1841 = { 4b 2e [2] 6f 20 [2] 44 0c [2] 6a 2e [2] 7e 35 [2] 71 2f [2] 6f 32 [2] 6d 33 [2] 76 35 [2] 6a 32 [2] 76 1d }

  condition:
    any of them
}