rule TTP_XOR_QUAD_CurrentVersionRun_3406 {
  strings:
    $key_3406 = { 67 69 [2] 43 67 [2] 68 4b [2] 46 69 [2] 52 72 [2] 5d 68 [2] 43 75 [2] 41 74 [2] 5a 72 [2] 46 75 [2] 5a 5a }

  condition:
    any of them
}