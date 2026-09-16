rule TTP_XOR_QUAD_CurrentVersionRun_2d76 {
  strings:
    $key_2d76 = { 7e 19 [2] 5a 17 [2] 71 3b [2] 5f 19 [2] 4b 02 [2] 44 18 [2] 5a 05 [2] 58 04 [2] 43 02 [2] 5f 05 [2] 43 2a }

  condition:
    any of them
}