rule TTP_XOR_QUAD_CurrentVersionRun_2e56 {
  strings:
    $key_2e56 = { 7d 39 [2] 59 37 [2] 72 1b [2] 5c 39 [2] 48 22 [2] 47 38 [2] 59 25 [2] 5b 24 [2] 40 22 [2] 5c 25 [2] 40 0a }

  condition:
    any of them
}