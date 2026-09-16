rule TTP_XOR_QUAD_CurrentVersionRun_5d18 {
  strings:
    $key_5d18 = { 0e 77 [2] 2a 79 [2] 01 55 [2] 2f 77 [2] 3b 6c [2] 34 76 [2] 2a 6b [2] 28 6a [2] 33 6c [2] 2f 6b [2] 33 44 }

  condition:
    any of them
}