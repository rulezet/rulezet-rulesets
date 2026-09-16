rule TTP_XOR_QUAD_CurrentVersionRun_0539 {
  strings:
    $key_0539 = { 56 56 [2] 72 58 [2] 59 74 [2] 77 56 [2] 63 4d [2] 6c 57 [2] 72 4a [2] 70 4b [2] 6b 4d [2] 77 4a [2] 6b 65 }

  condition:
    any of them
}