rule TTP_XOR_QUAD_CurrentVersionRun_3476 {
  strings:
    $key_3476 = { 67 19 [2] 43 17 [2] 68 3b [2] 46 19 [2] 52 02 [2] 5d 18 [2] 43 05 [2] 41 04 [2] 5a 02 [2] 46 05 [2] 5a 2a }

  condition:
    any of them
}