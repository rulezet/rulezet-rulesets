rule TTP_XOR_QUAD_CurrentVersionRun_1144 {
  strings:
    $key_1144 = { 42 2b [2] 66 25 [2] 4d 09 [2] 63 2b [2] 77 30 [2] 78 2a [2] 66 37 [2] 64 36 [2] 7f 30 [2] 63 37 [2] 7f 18 }

  condition:
    any of them
}