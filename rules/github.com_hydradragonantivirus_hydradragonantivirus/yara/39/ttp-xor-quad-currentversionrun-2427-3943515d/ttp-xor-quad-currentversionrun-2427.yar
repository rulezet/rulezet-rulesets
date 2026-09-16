rule TTP_XOR_QUAD_CurrentVersionRun_2427 {
  strings:
    $key_2427 = { 77 48 [2] 53 46 [2] 78 6a [2] 56 48 [2] 42 53 [2] 4d 49 [2] 53 54 [2] 51 55 [2] 4a 53 [2] 56 54 [2] 4a 7b }

  condition:
    any of them
}