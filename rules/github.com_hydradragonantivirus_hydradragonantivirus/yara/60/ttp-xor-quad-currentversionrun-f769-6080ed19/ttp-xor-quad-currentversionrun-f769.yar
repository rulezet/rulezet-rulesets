rule TTP_XOR_QUAD_CurrentVersionRun_f769 {
  strings:
    $key_f769 = { a4 06 [2] 80 08 [2] ab 24 [2] 85 06 [2] 91 1d [2] 9e 07 [2] 80 1a [2] 82 1b [2] 99 1d [2] 85 1a [2] 99 35 }

  condition:
    any of them
}