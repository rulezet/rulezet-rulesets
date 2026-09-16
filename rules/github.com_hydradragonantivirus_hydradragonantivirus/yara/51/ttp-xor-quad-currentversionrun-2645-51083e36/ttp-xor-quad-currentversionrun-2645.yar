rule TTP_XOR_QUAD_CurrentVersionRun_2645 {
  strings:
    $key_2645 = { 75 2a [2] 51 24 [2] 7a 08 [2] 54 2a [2] 40 31 [2] 4f 2b [2] 51 36 [2] 53 37 [2] 48 31 [2] 54 36 [2] 48 19 }

  condition:
    any of them
}