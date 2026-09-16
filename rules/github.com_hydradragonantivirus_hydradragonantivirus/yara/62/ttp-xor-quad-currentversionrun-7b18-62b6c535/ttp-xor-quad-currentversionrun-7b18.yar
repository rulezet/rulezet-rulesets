rule TTP_XOR_QUAD_CurrentVersionRun_7b18 {
  strings:
    $key_7b18 = { 28 77 [2] 0c 79 [2] 27 55 [2] 09 77 [2] 1d 6c [2] 12 76 [2] 0c 6b [2] 0e 6a [2] 15 6c [2] 09 6b [2] 15 44 }

  condition:
    any of them
}