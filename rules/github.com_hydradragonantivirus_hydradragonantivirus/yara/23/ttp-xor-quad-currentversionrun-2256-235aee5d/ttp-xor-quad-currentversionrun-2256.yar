rule TTP_XOR_QUAD_CurrentVersionRun_2256 {
  strings:
    $key_2256 = { 71 39 [2] 55 37 [2] 7e 1b [2] 50 39 [2] 44 22 [2] 4b 38 [2] 55 25 [2] 57 24 [2] 4c 22 [2] 50 25 [2] 4c 0a }

  condition:
    any of them
}