rule TTP_XOR_QUAD_CurrentVersionRun_3556 {
  strings:
    $key_3556 = { 66 39 [2] 42 37 [2] 69 1b [2] 47 39 [2] 53 22 [2] 5c 38 [2] 42 25 [2] 40 24 [2] 5b 22 [2] 47 25 [2] 5b 0a }

  condition:
    any of them
}