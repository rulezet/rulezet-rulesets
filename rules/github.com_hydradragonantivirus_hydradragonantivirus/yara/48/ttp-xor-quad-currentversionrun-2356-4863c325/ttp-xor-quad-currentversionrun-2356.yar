rule TTP_XOR_QUAD_CurrentVersionRun_2356 {
  strings:
    $key_2356 = { 70 39 [2] 54 37 [2] 7f 1b [2] 51 39 [2] 45 22 [2] 4a 38 [2] 54 25 [2] 56 24 [2] 4d 22 [2] 51 25 [2] 4d 0a }

  condition:
    any of them
}