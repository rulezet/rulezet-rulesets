rule TTP_XOR_QUAD_CurrentVersionRun_6022 {
  strings:
    $key_6022 = { 33 4d [2] 17 43 [2] 3c 6f [2] 12 4d [2] 06 56 [2] 09 4c [2] 17 51 [2] 15 50 [2] 0e 56 [2] 12 51 [2] 0e 7e }

  condition:
    any of them
}