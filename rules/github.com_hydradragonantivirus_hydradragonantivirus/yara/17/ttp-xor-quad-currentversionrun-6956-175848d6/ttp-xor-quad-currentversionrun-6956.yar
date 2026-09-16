rule TTP_XOR_QUAD_CurrentVersionRun_6956 {
  strings:
    $key_6956 = { 3a 39 [2] 1e 37 [2] 35 1b [2] 1b 39 [2] 0f 22 [2] 00 38 [2] 1e 25 [2] 1c 24 [2] 07 22 [2] 1b 25 [2] 07 0a }

  condition:
    any of them
}