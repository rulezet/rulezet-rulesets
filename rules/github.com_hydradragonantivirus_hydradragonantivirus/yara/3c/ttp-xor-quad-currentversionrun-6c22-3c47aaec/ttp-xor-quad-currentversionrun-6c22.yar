rule TTP_XOR_QUAD_CurrentVersionRun_6c22 {
  strings:
    $key_6c22 = { 3f 4d [2] 1b 43 [2] 30 6f [2] 1e 4d [2] 0a 56 [2] 05 4c [2] 1b 51 [2] 19 50 [2] 02 56 [2] 1e 51 [2] 02 7e }

  condition:
    any of them
}