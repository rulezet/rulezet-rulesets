rule TTP_XOR_QUAD_CurrentVersionRun_f775 {
  strings:
    $key_f775 = { a4 1a [2] 80 14 [2] ab 38 [2] 85 1a [2] 91 01 [2] 9e 1b [2] 80 06 [2] 82 07 [2] 99 01 [2] 85 06 [2] 99 29 }

  condition:
    any of them
}