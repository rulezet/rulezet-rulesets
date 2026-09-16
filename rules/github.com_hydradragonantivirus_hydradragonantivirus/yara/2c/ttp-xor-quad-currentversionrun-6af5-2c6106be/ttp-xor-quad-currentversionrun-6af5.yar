rule TTP_XOR_QUAD_CurrentVersionRun_6af5 {
  strings:
    $key_6af5 = { 39 9a [2] 1d 94 [2] 36 b8 [2] 18 9a [2] 0c 81 [2] 03 9b [2] 1d 86 [2] 1f 87 [2] 04 81 [2] 18 86 [2] 04 a9 }

  condition:
    any of them
}