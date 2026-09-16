rule TTP_XOR_QUAD_CurrentVersionRun_1178 {
  strings:
    $key_1178 = { 42 17 [2] 66 19 [2] 4d 35 [2] 63 17 [2] 77 0c [2] 78 16 [2] 66 0b [2] 64 0a [2] 7f 0c [2] 63 0b [2] 7f 24 }

  condition:
    any of them
}