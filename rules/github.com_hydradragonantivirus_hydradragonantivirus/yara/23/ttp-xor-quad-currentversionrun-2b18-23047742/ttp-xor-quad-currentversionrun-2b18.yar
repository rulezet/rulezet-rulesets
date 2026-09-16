rule TTP_XOR_QUAD_CurrentVersionRun_2b18 {
  strings:
    $key_2b18 = { 78 77 [2] 5c 79 [2] 77 55 [2] 59 77 [2] 4d 6c [2] 42 76 [2] 5c 6b [2] 5e 6a [2] 45 6c [2] 59 6b [2] 45 44 }

  condition:
    any of them
}