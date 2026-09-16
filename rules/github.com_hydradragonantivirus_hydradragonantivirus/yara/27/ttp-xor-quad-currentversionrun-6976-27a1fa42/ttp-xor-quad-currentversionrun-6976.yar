rule TTP_XOR_QUAD_CurrentVersionRun_6976 {
  strings:
    $key_6976 = { 3a 19 [2] 1e 17 [2] 35 3b [2] 1b 19 [2] 0f 02 [2] 00 18 [2] 1e 05 [2] 1c 04 [2] 07 02 [2] 1b 05 [2] 07 2a }

  condition:
    any of them
}