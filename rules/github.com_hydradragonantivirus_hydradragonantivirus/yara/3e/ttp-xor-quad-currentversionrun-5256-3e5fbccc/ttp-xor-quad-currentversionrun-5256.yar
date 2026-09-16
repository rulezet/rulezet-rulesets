rule TTP_XOR_QUAD_CurrentVersionRun_5256 {
  strings:
    $key_5256 = { 01 39 [2] 25 37 [2] 0e 1b [2] 20 39 [2] 34 22 [2] 3b 38 [2] 25 25 [2] 27 24 [2] 3c 22 [2] 20 25 [2] 3c 0a }

  condition:
    any of them
}