rule TTP_XOR_QUAD_CurrentVersionRun_7b22 {
  strings:
    $key_7b22 = { 28 4d [2] 0c 43 [2] 27 6f [2] 09 4d [2] 1d 56 [2] 12 4c [2] 0c 51 [2] 0e 50 [2] 15 56 [2] 09 51 [2] 15 7e }

  condition:
    any of them
}