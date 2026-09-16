rule TTP_XOR_QUAD_CurrentVersionRun_2415 {
  strings:
    $key_2415 = { 77 7a [2] 53 74 [2] 78 58 [2] 56 7a [2] 42 61 [2] 4d 7b [2] 53 66 [2] 51 67 [2] 4a 61 [2] 56 66 [2] 4a 49 }

  condition:
    any of them
}