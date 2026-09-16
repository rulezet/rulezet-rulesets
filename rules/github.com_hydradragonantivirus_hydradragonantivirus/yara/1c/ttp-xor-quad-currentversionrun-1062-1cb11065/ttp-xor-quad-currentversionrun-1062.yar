rule TTP_XOR_QUAD_CurrentVersionRun_1062 {
  strings:
    $key_1062 = { 43 0d [2] 67 03 [2] 4c 2f [2] 62 0d [2] 76 16 [2] 79 0c [2] 67 11 [2] 65 10 [2] 7e 16 [2] 62 11 [2] 7e 3e }

  condition:
    any of them
}