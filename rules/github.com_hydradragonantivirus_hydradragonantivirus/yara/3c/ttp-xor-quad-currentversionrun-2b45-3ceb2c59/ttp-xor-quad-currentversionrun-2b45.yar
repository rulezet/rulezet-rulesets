rule TTP_XOR_QUAD_CurrentVersionRun_2b45 {
  strings:
    $key_2b45 = { 78 2a [2] 5c 24 [2] 77 08 [2] 59 2a [2] 4d 31 [2] 42 2b [2] 5c 36 [2] 5e 37 [2] 45 31 [2] 59 36 [2] 45 19 }

  condition:
    any of them
}