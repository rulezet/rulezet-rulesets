rule TTP_XOR_QUAD_CurrentVersionRun_4e18 {
  strings:
    $key_4e18 = { 1d 77 [2] 39 79 [2] 12 55 [2] 3c 77 [2] 28 6c [2] 27 76 [2] 39 6b [2] 3b 6a [2] 20 6c [2] 3c 6b [2] 20 44 }

  condition:
    any of them
}