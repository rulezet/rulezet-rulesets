rule TTP_XOR_QUAD_CurrentVersionRun_f707 {
  strings:
    $key_f707 = { a4 68 [2] 80 66 [2] ab 4a [2] 85 68 [2] 91 73 [2] 9e 69 [2] 80 74 [2] 82 75 [2] 99 73 [2] 85 74 [2] 99 5b }

  condition:
    any of them
}