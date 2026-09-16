rule TTP_XOR_QUAD_CurrentVersionRun_f538 {
  strings:
    $key_f538 = { a6 57 [2] 82 59 [2] a9 75 [2] 87 57 [2] 93 4c [2] 9c 56 [2] 82 4b [2] 80 4a [2] 9b 4c [2] 87 4b [2] 9b 64 }

  condition:
    any of them
}