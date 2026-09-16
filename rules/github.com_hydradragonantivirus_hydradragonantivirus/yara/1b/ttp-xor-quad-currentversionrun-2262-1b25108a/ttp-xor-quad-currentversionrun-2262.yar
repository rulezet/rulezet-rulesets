rule TTP_XOR_QUAD_CurrentVersionRun_2262 {
  strings:
    $key_2262 = { 71 0d [2] 55 03 [2] 7e 2f [2] 50 0d [2] 44 16 [2] 4b 0c [2] 55 11 [2] 57 10 [2] 4c 16 [2] 50 11 [2] 4c 3e }

  condition:
    any of them
}