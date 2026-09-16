rule TTP_XOR_QUAD_CurrentVersionRun_1138 {
  strings:
    $key_1138 = { 42 57 [2] 66 59 [2] 4d 75 [2] 63 57 [2] 77 4c [2] 78 56 [2] 66 4b [2] 64 4a [2] 7f 4c [2] 63 4b [2] 7f 64 }

  condition:
    any of them
}