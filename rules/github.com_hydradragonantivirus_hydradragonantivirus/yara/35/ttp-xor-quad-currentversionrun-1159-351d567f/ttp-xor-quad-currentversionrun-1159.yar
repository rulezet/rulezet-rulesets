rule TTP_XOR_QUAD_CurrentVersionRun_1159 {
  strings:
    $key_1159 = { 42 36 [2] 66 38 [2] 4d 14 [2] 63 36 [2] 77 2d [2] 78 37 [2] 66 2a [2] 64 2b [2] 7f 2d [2] 63 2a [2] 7f 05 }

  condition:
    any of them
}