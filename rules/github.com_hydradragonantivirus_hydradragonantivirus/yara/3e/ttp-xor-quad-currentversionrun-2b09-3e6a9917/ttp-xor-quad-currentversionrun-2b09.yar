rule TTP_XOR_QUAD_CurrentVersionRun_2b09 {
  strings:
    $key_2b09 = { 78 66 [2] 5c 68 [2] 77 44 [2] 59 66 [2] 4d 7d [2] 42 67 [2] 5c 7a [2] 5e 7b [2] 45 7d [2] 59 7a [2] 45 55 }

  condition:
    any of them
}