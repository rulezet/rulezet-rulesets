rule TTP_XOR_QUAD_CurrentVersionRun_2463 {
  strings:
    $key_2463 = { 77 0c [2] 53 02 [2] 78 2e [2] 56 0c [2] 42 17 [2] 4d 0d [2] 53 10 [2] 51 11 [2] 4a 17 [2] 56 10 [2] 4a 3f }

  condition:
    any of them
}