rule TTP_XOR_QUAD_CurrentVersionRun_2e76 {
  strings:
    $key_2e76 = { 7d 19 [2] 59 17 [2] 72 3b [2] 5c 19 [2] 48 02 [2] 47 18 [2] 59 05 [2] 5b 04 [2] 40 02 [2] 5c 05 [2] 40 2a }

  condition:
    any of them
}