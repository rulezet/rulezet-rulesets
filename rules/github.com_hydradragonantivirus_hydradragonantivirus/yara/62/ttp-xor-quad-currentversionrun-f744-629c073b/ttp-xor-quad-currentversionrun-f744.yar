rule TTP_XOR_QUAD_CurrentVersionRun_f744 {
  strings:
    $key_f744 = { a4 2b [2] 80 25 [2] ab 09 [2] 85 2b [2] 91 30 [2] 9e 2a [2] 80 37 [2] 82 36 [2] 99 30 [2] 85 37 [2] 99 18 }

  condition:
    any of them
}