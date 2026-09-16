rule TTP_XOR_QUAD_CurrentVersionRun_2762 {
  strings:
    $key_2762 = { 74 0d [2] 50 03 [2] 7b 2f [2] 55 0d [2] 41 16 [2] 4e 0c [2] 50 11 [2] 52 10 [2] 49 16 [2] 55 11 [2] 49 3e }

  condition:
    any of them
}