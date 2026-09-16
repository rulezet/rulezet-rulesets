rule TTP_XOR_QUAD_CurrentVersionRun_3444 {
  strings:
    $key_3444 = { 67 2b [2] 43 25 [2] 68 09 [2] 46 2b [2] 52 30 [2] 5d 2a [2] 43 37 [2] 41 36 [2] 5a 30 [2] 46 37 [2] 5a 18 }

  condition:
    any of them
}