rule TTP_XOR_QUAD_CurrentVersionRun_2718 {
  strings:
    $key_2718 = { 74 77 [2] 50 79 [2] 7b 55 [2] 55 77 [2] 41 6c [2] 4e 76 [2] 50 6b [2] 52 6a [2] 49 6c [2] 55 6b [2] 49 44 }

  condition:
    any of them
}