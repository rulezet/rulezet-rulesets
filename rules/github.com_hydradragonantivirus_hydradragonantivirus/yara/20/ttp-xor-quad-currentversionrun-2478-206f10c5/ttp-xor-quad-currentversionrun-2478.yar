rule TTP_XOR_QUAD_CurrentVersionRun_2478 {
  strings:
    $key_2478 = { 77 17 [2] 53 19 [2] 78 35 [2] 56 17 [2] 42 0c [2] 4d 16 [2] 53 0b [2] 51 0a [2] 4a 0c [2] 56 0b [2] 4a 24 }

  condition:
    any of them
}