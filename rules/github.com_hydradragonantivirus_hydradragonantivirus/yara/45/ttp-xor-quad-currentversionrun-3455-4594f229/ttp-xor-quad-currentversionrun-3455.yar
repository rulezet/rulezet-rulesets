rule TTP_XOR_QUAD_CurrentVersionRun_3455 {
  strings:
    $key_3455 = { 67 3a [2] 43 34 [2] 68 18 [2] 46 3a [2] 52 21 [2] 5d 3b [2] 43 26 [2] 41 27 [2] 5a 21 [2] 46 26 [2] 5a 09 }

  condition:
    any of them
}