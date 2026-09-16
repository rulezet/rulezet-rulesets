rule TTP_XOR_QUAD_CurrentVersionRun_4b18 {
  strings:
    $key_4b18 = { 18 77 [2] 3c 79 [2] 17 55 [2] 39 77 [2] 2d 6c [2] 22 76 [2] 3c 6b [2] 3e 6a [2] 25 6c [2] 39 6b [2] 25 44 }

  condition:
    any of them
}