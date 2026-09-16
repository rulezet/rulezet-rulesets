rule TTP_XOR_QUAD_CurrentVersionRun_2876 {
  strings:
    $key_2876 = { 7b 19 [2] 5f 17 [2] 74 3b [2] 5a 19 [2] 4e 02 [2] 41 18 [2] 5f 05 [2] 5d 04 [2] 46 02 [2] 5a 05 [2] 46 2a }

  condition:
    any of them
}