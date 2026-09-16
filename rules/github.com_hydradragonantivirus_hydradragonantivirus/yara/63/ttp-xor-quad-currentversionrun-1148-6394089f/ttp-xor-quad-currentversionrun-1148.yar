rule TTP_XOR_QUAD_CurrentVersionRun_1148 {
  strings:
    $key_1148 = { 42 27 [2] 66 29 [2] 4d 05 [2] 63 27 [2] 77 3c [2] 78 26 [2] 66 3b [2] 64 3a [2] 7f 3c [2] 63 3b [2] 7f 14 }

  condition:
    any of them
}