rule TTP_XOR_QUAD_CurrentVersionRun_f218 {
  strings:
    $key_f218 = { a1 77 [2] 85 79 [2] ae 55 [2] 80 77 [2] 94 6c [2] 9b 76 [2] 85 6b [2] 87 6a [2] 9c 6c [2] 80 6b [2] 9c 44 }

  condition:
    any of them
}