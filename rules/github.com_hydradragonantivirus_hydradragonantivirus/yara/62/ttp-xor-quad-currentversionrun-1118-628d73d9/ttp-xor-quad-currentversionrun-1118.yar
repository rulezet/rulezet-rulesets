rule TTP_XOR_QUAD_CurrentVersionRun_1118 {
  strings:
    $key_1118 = { 42 77 [2] 66 79 [2] 4d 55 [2] 63 77 [2] 77 6c [2] 78 76 [2] 66 6b [2] 64 6a [2] 7f 6c [2] 63 6b [2] 7f 44 }

  condition:
    any of them
}