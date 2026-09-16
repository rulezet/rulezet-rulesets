rule TTP_XOR_QUAD_CurrentVersionRun_342b {
  strings:
    $key_342b = { 67 44 [2] 43 4a [2] 68 66 [2] 46 44 [2] 52 5f [2] 5d 45 [2] 43 58 [2] 41 59 [2] 5a 5f [2] 46 58 [2] 5a 77 }

  condition:
    any of them
}