rule TTP_XOR_QUAD_CurrentVersionRun_3c56 {
  strings:
    $key_3c56 = { 6f 39 [2] 4b 37 [2] 60 1b [2] 4e 39 [2] 5a 22 [2] 55 38 [2] 4b 25 [2] 49 24 [2] 52 22 [2] 4e 25 [2] 52 0a }

  condition:
    any of them
}