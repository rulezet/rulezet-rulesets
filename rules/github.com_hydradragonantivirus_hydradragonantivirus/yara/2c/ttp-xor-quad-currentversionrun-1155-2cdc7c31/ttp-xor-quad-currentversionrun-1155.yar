rule TTP_XOR_QUAD_CurrentVersionRun_1155 {
  strings:
    $key_1155 = { 42 3a [2] 66 34 [2] 4d 18 [2] 63 3a [2] 77 21 [2] 78 3b [2] 66 26 [2] 64 27 [2] 7f 21 [2] 63 26 [2] 7f 09 }

  condition:
    any of them
}