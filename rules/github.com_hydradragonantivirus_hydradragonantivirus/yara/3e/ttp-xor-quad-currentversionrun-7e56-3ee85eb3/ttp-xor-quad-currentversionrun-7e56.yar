rule TTP_XOR_QUAD_CurrentVersionRun_7e56 {
  strings:
    $key_7e56 = { 2d 39 [2] 09 37 [2] 22 1b [2] 0c 39 [2] 18 22 [2] 17 38 [2] 09 25 [2] 0b 24 [2] 10 22 [2] 0c 25 [2] 10 0a }

  condition:
    any of them
}