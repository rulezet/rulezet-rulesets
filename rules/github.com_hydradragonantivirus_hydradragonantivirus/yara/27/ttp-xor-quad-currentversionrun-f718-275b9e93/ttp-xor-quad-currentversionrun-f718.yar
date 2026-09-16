rule TTP_XOR_QUAD_CurrentVersionRun_f718 {
  strings:
    $key_f718 = { a4 77 [2] 80 79 [2] ab 55 [2] 85 77 [2] 91 6c [2] 9e 76 [2] 80 6b [2] 82 6a [2] 99 6c [2] 85 6b [2] 99 44 }

  condition:
    any of them
}