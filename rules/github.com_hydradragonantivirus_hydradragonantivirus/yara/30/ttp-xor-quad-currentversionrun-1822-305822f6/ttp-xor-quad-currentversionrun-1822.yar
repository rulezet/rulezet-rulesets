rule TTP_XOR_QUAD_CurrentVersionRun_1822 {
  strings:
    $key_1822 = { 4b 4d [2] 6f 43 [2] 44 6f [2] 6a 4d [2] 7e 56 [2] 71 4c [2] 6f 51 [2] 6d 50 [2] 76 56 [2] 6a 51 [2] 76 7e }

  condition:
    any of them
}