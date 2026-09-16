rule TTP_XOR_QUAD_CurrentVersionRun_05f4 {
  strings:
    $key_05f4 = { 56 9b [2] 72 95 [2] 59 b9 [2] 77 9b [2] 63 80 [2] 6c 9a [2] 72 87 [2] 70 86 [2] 6b 80 [2] 77 87 [2] 6b a8 }

  condition:
    any of them
}