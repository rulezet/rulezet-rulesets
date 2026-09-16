rule TTP_XOR_QUAD_CurrentVersionRun_2976 {
  strings:
    $key_2976 = { 7a 19 [2] 5e 17 [2] 75 3b [2] 5b 19 [2] 4f 02 [2] 40 18 [2] 5e 05 [2] 5c 04 [2] 47 02 [2] 5b 05 [2] 47 2a }

  condition:
    any of them
}