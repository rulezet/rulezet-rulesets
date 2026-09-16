rule TTP_XOR_QUAD_CurrentVersionRun_6c76 {
  strings:
    $key_6c76 = { 3f 19 [2] 1b 17 [2] 30 3b [2] 1e 19 [2] 0a 02 [2] 05 18 [2] 1b 05 [2] 19 04 [2] 02 02 [2] 1e 05 [2] 02 2a }

  condition:
    any of them
}