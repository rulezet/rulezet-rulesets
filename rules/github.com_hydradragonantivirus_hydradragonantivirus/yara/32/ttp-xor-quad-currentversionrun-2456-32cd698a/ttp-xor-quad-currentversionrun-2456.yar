rule TTP_XOR_QUAD_CurrentVersionRun_2456 {
  strings:
    $key_2456 = { 77 39 [2] 53 37 [2] 78 1b [2] 56 39 [2] 42 22 [2] 4d 38 [2] 53 25 [2] 51 24 [2] 4a 22 [2] 56 25 [2] 4a 0a }

  condition:
    any of them
}