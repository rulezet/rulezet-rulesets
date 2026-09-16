rule TTP_XOR_QUAD_CurrentVersionRun_6c56 {
  strings:
    $key_6c56 = { 3f 39 [2] 1b 37 [2] 30 1b [2] 1e 39 [2] 0a 22 [2] 05 38 [2] 1b 25 [2] 19 24 [2] 02 22 [2] 1e 25 [2] 02 0a }

  condition:
    any of them
}