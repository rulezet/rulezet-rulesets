rule TTP_XOR_QUAD_CurrentVersionRun_312b {
  strings:
    $key_312b = { 62 44 [2] 46 4a [2] 6d 66 [2] 43 44 [2] 57 5f [2] 58 45 [2] 46 58 [2] 44 59 [2] 5f 5f [2] 43 58 [2] 5f 77 }

  condition:
    any of them
}