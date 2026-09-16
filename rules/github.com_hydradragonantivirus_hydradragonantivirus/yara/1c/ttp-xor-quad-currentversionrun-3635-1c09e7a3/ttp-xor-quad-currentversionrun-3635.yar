rule TTP_XOR_QUAD_CurrentVersionRun_3635 {
  strings:
    $key_3635 = { 65 5a [2] 41 54 [2] 6a 78 [2] 44 5a [2] 50 41 [2] 5f 5b [2] 41 46 [2] 43 47 [2] 58 41 [2] 44 46 [2] 58 69 }

  condition:
    any of them
}