rule TTP_XOR_QUAD_CurrentVersionRun_3459 {
  strings:
    $key_3459 = { 67 36 [2] 43 38 [2] 68 14 [2] 46 36 [2] 52 2d [2] 5d 37 [2] 43 2a [2] 41 2b [2] 5a 2d [2] 46 2a [2] 5a 05 }

  condition:
    any of them
}