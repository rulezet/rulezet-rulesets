rule TTP_XOR_QUAD_CurrentVersionRun_2418 {
  strings:
    $key_2418 = { 77 77 [2] 53 79 [2] 78 55 [2] 56 77 [2] 42 6c [2] 4d 76 [2] 53 6b [2] 51 6a [2] 4a 6c [2] 56 6b [2] 4a 44 }

  condition:
    any of them
}