rule TTP_XOR_QUAD_CurrentVersionRun_3424 {
  strings:
    $key_3424 = { 67 4b [2] 43 45 [2] 68 69 [2] 46 4b [2] 52 50 [2] 5d 4a [2] 43 57 [2] 41 56 [2] 5a 50 [2] 46 57 [2] 5a 78 }

  condition:
    any of them
}