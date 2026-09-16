rule TTP_XOR_QUAD_CurrentVersionRun_4976 {
  strings:
    $key_4976 = { 1a 19 [2] 3e 17 [2] 15 3b [2] 3b 19 [2] 2f 02 [2] 20 18 [2] 3e 05 [2] 3c 04 [2] 27 02 [2] 3b 05 [2] 27 2a }

  condition:
    any of them
}