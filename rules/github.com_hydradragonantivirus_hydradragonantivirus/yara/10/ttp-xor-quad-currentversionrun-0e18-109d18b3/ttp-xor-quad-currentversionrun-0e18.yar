rule TTP_XOR_QUAD_CurrentVersionRun_0e18 {
  strings:
    $key_0e18 = { 5d 77 [2] 79 79 [2] 52 55 [2] 7c 77 [2] 68 6c [2] 67 76 [2] 79 6b [2] 7b 6a [2] 60 6c [2] 7c 6b [2] 60 44 }

  condition:
    any of them
}