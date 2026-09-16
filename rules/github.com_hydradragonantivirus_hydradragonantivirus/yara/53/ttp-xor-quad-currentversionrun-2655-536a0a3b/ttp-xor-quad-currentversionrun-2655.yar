rule TTP_XOR_QUAD_CurrentVersionRun_2655 {
  strings:
    $key_2655 = { 75 3a [2] 51 34 [2] 7a 18 [2] 54 3a [2] 40 21 [2] 4f 3b [2] 51 26 [2] 53 27 [2] 48 21 [2] 54 26 [2] 48 09 }

  condition:
    any of them
}