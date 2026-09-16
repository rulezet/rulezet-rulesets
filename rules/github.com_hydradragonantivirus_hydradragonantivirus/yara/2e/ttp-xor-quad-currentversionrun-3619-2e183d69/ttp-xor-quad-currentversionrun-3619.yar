rule TTP_XOR_QUAD_CurrentVersionRun_3619 {
  strings:
    $key_3619 = { 65 76 [2] 41 78 [2] 6a 54 [2] 44 76 [2] 50 6d [2] 5f 77 [2] 41 6a [2] 43 6b [2] 58 6d [2] 44 6a [2] 58 45 }

  condition:
    any of them
}