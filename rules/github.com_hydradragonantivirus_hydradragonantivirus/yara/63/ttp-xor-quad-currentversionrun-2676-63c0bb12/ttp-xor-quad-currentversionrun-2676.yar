rule TTP_XOR_QUAD_CurrentVersionRun_2676 {
  strings:
    $key_2676 = { 75 19 [2] 51 17 [2] 7a 3b [2] 54 19 [2] 40 02 [2] 4f 18 [2] 51 05 [2] 53 04 [2] 48 02 [2] 54 05 [2] 48 2a }

  condition:
    any of them
}