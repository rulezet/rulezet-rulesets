rule TTP_XOR_QUAD_CurrentVersionRun_2363 {
  strings:
    $key_2363 = { 70 0c [2] 54 02 [2] 7f 2e [2] 51 0c [2] 45 17 [2] 4a 0d [2] 54 10 [2] 56 11 [2] 4d 17 [2] 51 10 [2] 4d 3f }

  condition:
    any of them
}