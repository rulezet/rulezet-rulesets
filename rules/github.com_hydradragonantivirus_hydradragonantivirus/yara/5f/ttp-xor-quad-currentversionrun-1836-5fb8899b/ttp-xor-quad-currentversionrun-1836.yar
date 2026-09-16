rule TTP_XOR_QUAD_CurrentVersionRun_1836 {
  strings:
    $key_1836 = { 4b 59 [2] 6f 57 [2] 44 7b [2] 6a 59 [2] 7e 42 [2] 71 58 [2] 6f 45 [2] 6d 44 [2] 76 42 [2] 6a 45 [2] 76 6a }

  condition:
    any of them
}