rule TTP_XOR_QUAD_CurrentVersionRun_2376 {
  strings:
    $key_2376 = { 70 19 [2] 54 17 [2] 7f 3b [2] 51 19 [2] 45 02 [2] 4a 18 [2] 54 05 [2] 56 04 [2] 4d 02 [2] 51 05 [2] 4d 2a }

  condition:
    any of them
}