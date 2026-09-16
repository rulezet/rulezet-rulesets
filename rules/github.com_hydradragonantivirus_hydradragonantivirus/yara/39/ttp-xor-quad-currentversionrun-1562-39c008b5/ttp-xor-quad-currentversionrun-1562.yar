rule TTP_XOR_QUAD_CurrentVersionRun_1562 {
  strings:
    $key_1562 = { 46 0d [2] 62 03 [2] 49 2f [2] 67 0d [2] 73 16 [2] 7c 0c [2] 62 11 [2] 60 10 [2] 7b 16 [2] 67 11 [2] 7b 3e }

  condition:
    any of them
}