rule TTP_XOR_QUAD_CurrentVersionRun_f759 {
  strings:
    $key_f759 = { a4 36 [2] 80 38 [2] ab 14 [2] 85 36 [2] 91 2d [2] 9e 37 [2] 80 2a [2] 82 2b [2] 99 2d [2] 85 2a [2] 99 05 }

  condition:
    any of them
}