rule TTP_XOR_QUAD_CurrentVersionRun_5518 {
  strings:
    $key_5518 = { 06 77 [2] 22 79 [2] 09 55 [2] 27 77 [2] 33 6c [2] 3c 76 [2] 22 6b [2] 20 6a [2] 3b 6c [2] 27 6b [2] 3b 44 }

  condition:
    any of them
}