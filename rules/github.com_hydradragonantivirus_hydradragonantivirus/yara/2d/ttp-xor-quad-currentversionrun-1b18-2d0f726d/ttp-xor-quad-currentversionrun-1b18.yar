rule TTP_XOR_QUAD_CurrentVersionRun_1b18 {
  strings:
    $key_1b18 = { 48 77 [2] 6c 79 [2] 47 55 [2] 69 77 [2] 7d 6c [2] 72 76 [2] 6c 6b [2] 6e 6a [2] 75 6c [2] 69 6b [2] 75 44 }

  condition:
    any of them
}