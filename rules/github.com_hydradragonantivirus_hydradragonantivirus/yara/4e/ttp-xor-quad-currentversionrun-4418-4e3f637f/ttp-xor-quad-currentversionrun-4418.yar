rule TTP_XOR_QUAD_CurrentVersionRun_4418 {
  strings:
    $key_4418 = { 17 77 [2] 33 79 [2] 18 55 [2] 36 77 [2] 22 6c [2] 2d 76 [2] 33 6b [2] 31 6a [2] 2a 6c [2] 36 6b [2] 2a 44 }

  condition:
    any of them
}