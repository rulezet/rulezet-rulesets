rule TTP_XOR_QUAD_CurrentVersionRun_7d76 {
  strings:
    $key_7d76 = { 2e 19 [2] 0a 17 [2] 21 3b [2] 0f 19 [2] 1b 02 [2] 14 18 [2] 0a 05 [2] 08 04 [2] 13 02 [2] 0f 05 [2] 13 2a }

  condition:
    any of them
}