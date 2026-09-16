rule TTP_XOR_QUAD_CurrentVersionRun_6f18 {
  strings:
    $key_6f18 = { 3c 77 [2] 18 79 [2] 33 55 [2] 1d 77 [2] 09 6c [2] 06 76 [2] 18 6b [2] 1a 6a [2] 01 6c [2] 1d 6b [2] 01 44 }

  condition:
    any of them
}