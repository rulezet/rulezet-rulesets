rule TTP_XOR_QUAD_CurrentVersionRun_3e76 {
  strings:
    $key_3e76 = { 6d 19 [2] 49 17 [2] 62 3b [2] 4c 19 [2] 58 02 [2] 57 18 [2] 49 05 [2] 4b 04 [2] 50 02 [2] 4c 05 [2] 50 2a }

  condition:
    any of them
}