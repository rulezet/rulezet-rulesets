rule TTP_XOR_QUAD_CurrentVersionRun_3b56 {
  strings:
    $key_3b56 = { 68 39 [2] 4c 37 [2] 67 1b [2] 49 39 [2] 5d 22 [2] 52 38 [2] 4c 25 [2] 4e 24 [2] 55 22 [2] 49 25 [2] 55 0a }

  condition:
    any of them
}