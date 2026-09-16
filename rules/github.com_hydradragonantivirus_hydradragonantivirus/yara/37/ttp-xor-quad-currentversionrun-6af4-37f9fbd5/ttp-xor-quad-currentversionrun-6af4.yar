rule TTP_XOR_QUAD_CurrentVersionRun_6af4 {
  strings:
    $key_6af4 = { 39 9b [2] 1d 95 [2] 36 b9 [2] 18 9b [2] 0c 80 [2] 03 9a [2] 1d 87 [2] 1f 86 [2] 04 80 [2] 18 87 [2] 04 a8 }

  condition:
    any of them
}