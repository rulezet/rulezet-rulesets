rule TTP_XOR_QUAD_CurrentVersionRun_2b76 {
  strings:
    $key_2b76 = { 78 19 [2] 5c 17 [2] 77 3b [2] 59 19 [2] 4d 02 [2] 42 18 [2] 5c 05 [2] 5e 04 [2] 45 02 [2] 59 05 [2] 45 2a }

  condition:
    any of them
}