rule TTP_XOR_QUAD_CurrentVersionRun_1145 {
  strings:
    $key_1145 = { 42 2a [2] 66 24 [2] 4d 08 [2] 63 2a [2] 77 31 [2] 78 2b [2] 66 36 [2] 64 37 [2] 7f 31 [2] 63 36 [2] 7f 19 }

  condition:
    any of them
}