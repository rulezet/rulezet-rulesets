rule TTP_XOR_QUAD_CurrentVersionRun_f418 {
  strings:
    $key_f418 = { a7 77 [2] 83 79 [2] a8 55 [2] 86 77 [2] 92 6c [2] 9d 76 [2] 83 6b [2] 81 6a [2] 9a 6c [2] 86 6b [2] 9a 44 }

  condition:
    any of them
}