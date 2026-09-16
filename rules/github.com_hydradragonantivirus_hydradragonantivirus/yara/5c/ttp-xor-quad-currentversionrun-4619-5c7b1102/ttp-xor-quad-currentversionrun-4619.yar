rule TTP_XOR_QUAD_CurrentVersionRun_4619 {
  strings:
    $key_4619 = { 15 76 [2] 31 78 [2] 1a 54 [2] 34 76 [2] 20 6d [2] 2f 77 [2] 31 6a [2] 33 6b [2] 28 6d [2] 34 6a [2] 28 45 }

  condition:
    any of them
}