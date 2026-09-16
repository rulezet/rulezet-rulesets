rule TTP_XOR_QUAD_CurrentVersionRun_2759 {
  strings:
    $key_2759 = { 74 36 [2] 50 38 [2] 7b 14 [2] 55 36 [2] 41 2d [2] 4e 37 [2] 50 2a [2] 52 2b [2] 49 2d [2] 55 2a [2] 49 05 }

  condition:
    any of them
}