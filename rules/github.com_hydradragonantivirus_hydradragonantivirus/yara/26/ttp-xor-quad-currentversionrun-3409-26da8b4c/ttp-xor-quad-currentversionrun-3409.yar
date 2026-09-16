rule TTP_XOR_QUAD_CurrentVersionRun_3409 {
  strings:
    $key_3409 = { 67 66 [2] 43 68 [2] 68 44 [2] 46 66 [2] 52 7d [2] 5d 67 [2] 43 7a [2] 41 7b [2] 5a 7d [2] 46 7a [2] 5a 55 }

  condition:
    any of them
}