rule TTP_XOR_QUAD_CurrentVersionRun_2b59 {
  strings:
    $key_2b59 = { 78 36 [2] 5c 38 [2] 77 14 [2] 59 36 [2] 4d 2d [2] 42 37 [2] 5c 2a [2] 5e 2b [2] 45 2d [2] 59 2a [2] 45 05 }

  condition:
    any of them
}