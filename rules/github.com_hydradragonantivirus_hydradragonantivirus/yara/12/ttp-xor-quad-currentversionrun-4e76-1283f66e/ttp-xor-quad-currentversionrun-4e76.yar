rule TTP_XOR_QUAD_CurrentVersionRun_4e76 {
  strings:
    $key_4e76 = { 1d 19 [2] 39 17 [2] 12 3b [2] 3c 19 [2] 28 02 [2] 27 18 [2] 39 05 [2] 3b 04 [2] 20 02 [2] 3c 05 [2] 20 2a }

  condition:
    any of them
}