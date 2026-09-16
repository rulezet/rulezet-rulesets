rule TTP_XOR_QUAD_CurrentVersionRun_f705 {
  strings:
    $key_f705 = { a4 6a [2] 80 64 [2] ab 48 [2] 85 6a [2] 91 71 [2] 9e 6b [2] 80 76 [2] 82 77 [2] 99 71 [2] 85 76 [2] 99 59 }

  condition:
    any of them
}