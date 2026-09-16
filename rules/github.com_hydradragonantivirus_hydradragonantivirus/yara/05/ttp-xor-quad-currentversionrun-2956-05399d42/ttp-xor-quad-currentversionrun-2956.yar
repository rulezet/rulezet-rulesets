rule TTP_XOR_QUAD_CurrentVersionRun_2956 {
  strings:
    $key_2956 = { 7a 39 [2] 5e 37 [2] 75 1b [2] 5b 39 [2] 4f 22 [2] 40 38 [2] 5e 25 [2] 5c 24 [2] 47 22 [2] 5b 25 [2] 47 0a }

  condition:
    any of them
}