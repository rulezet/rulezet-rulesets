rule TTP_XOR_QUAD_CurrentVersionRun_2b25 {
  strings:
    $key_2b25 = { 78 4a [2] 5c 44 [2] 77 68 [2] 59 4a [2] 4d 51 [2] 42 4b [2] 5c 56 [2] 5e 57 [2] 45 51 [2] 59 56 [2] 45 79 }

  condition:
    any of them
}