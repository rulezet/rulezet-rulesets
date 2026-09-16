rule TTP_XOR_QUAD_CurrentVersionRun_2862 {
  strings:
    $key_2862 = { 7b 0d [2] 5f 03 [2] 74 2f [2] 5a 0d [2] 4e 16 [2] 41 0c [2] 5f 11 [2] 5d 10 [2] 46 16 [2] 5a 11 [2] 46 3e }

  condition:
    any of them
}