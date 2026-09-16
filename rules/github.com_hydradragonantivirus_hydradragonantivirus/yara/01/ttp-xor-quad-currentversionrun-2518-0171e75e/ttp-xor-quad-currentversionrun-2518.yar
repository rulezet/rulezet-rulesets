rule TTP_XOR_QUAD_CurrentVersionRun_2518 {
  strings:
    $key_2518 = { 76 77 [2] 52 79 [2] 79 55 [2] 57 77 [2] 43 6c [2] 4c 76 [2] 52 6b [2] 50 6a [2] 4b 6c [2] 57 6b [2] 4b 44 }

  condition:
    any of them
}