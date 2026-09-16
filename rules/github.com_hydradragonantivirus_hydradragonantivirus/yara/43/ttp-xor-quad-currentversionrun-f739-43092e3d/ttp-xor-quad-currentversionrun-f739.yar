rule TTP_XOR_QUAD_CurrentVersionRun_f739 {
  strings:
    $key_f739 = { a4 56 [2] 80 58 [2] ab 74 [2] 85 56 [2] 91 4d [2] 9e 57 [2] 80 4a [2] 82 4b [2] 99 4d [2] 85 4a [2] 99 65 }

  condition:
    any of them
}