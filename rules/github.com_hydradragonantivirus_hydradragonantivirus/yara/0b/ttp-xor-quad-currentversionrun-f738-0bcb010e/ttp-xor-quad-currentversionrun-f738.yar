rule TTP_XOR_QUAD_CurrentVersionRun_f738 {
  strings:
    $key_f738 = { a4 57 [2] 80 59 [2] ab 75 [2] 85 57 [2] 91 4c [2] 9e 56 [2] 80 4b [2] 82 4a [2] 99 4c [2] 85 4b [2] 99 64 }

  condition:
    any of them
}