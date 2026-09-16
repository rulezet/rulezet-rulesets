rule TTP_XOR_QUAD_CurrentVersionRun_7956 {
  strings:
    $key_7956 = { 2a 39 [2] 0e 37 [2] 25 1b [2] 0b 39 [2] 1f 22 [2] 10 38 [2] 0e 25 [2] 0c 24 [2] 17 22 [2] 0b 25 [2] 17 0a }

  condition:
    any of them
}