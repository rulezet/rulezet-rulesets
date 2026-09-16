rule TTP_XOR_QUAD_CurrentVersionRun_2468 {
  strings:
    $key_2468 = { 77 07 [2] 53 09 [2] 78 25 [2] 56 07 [2] 42 1c [2] 4d 06 [2] 53 1b [2] 51 1a [2] 4a 1c [2] 56 1b [2] 4a 34 }

  condition:
    any of them
}