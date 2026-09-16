rule TTP_XOR_QUAD_CurrentVersionRun_2b39 {
  strings:
    $key_2b39 = { 78 56 [2] 5c 58 [2] 77 74 [2] 59 56 [2] 4d 4d [2] 42 57 [2] 5c 4a [2] 5e 4b [2] 45 4d [2] 59 4a [2] 45 65 }

  condition:
    any of them
}