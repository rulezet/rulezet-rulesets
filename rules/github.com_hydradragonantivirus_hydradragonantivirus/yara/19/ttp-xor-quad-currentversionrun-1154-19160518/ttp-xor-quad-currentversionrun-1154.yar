rule TTP_XOR_QUAD_CurrentVersionRun_1154 {
  strings:
    $key_1154 = { 42 3b [2] 66 35 [2] 4d 19 [2] 63 3b [2] 77 20 [2] 78 3a [2] 66 27 [2] 64 26 [2] 7f 20 [2] 63 27 [2] 7f 08 }

  condition:
    any of them
}