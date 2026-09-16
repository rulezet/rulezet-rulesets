rule TTP_XOR_QUAD_CurrentVersionRun_2b78 {
  strings:
    $key_2b78 = { 78 17 [2] 5c 19 [2] 77 35 [2] 59 17 [2] 4d 0c [2] 42 16 [2] 5c 0b [2] 5e 0a [2] 45 0c [2] 59 0b [2] 45 24 }

  condition:
    any of them
}