rule TTP_XOR_QUAD_CurrentVersionRun_6a25 {
  strings:
    $key_6a25 = { 39 4a [2] 1d 44 [2] 36 68 [2] 18 4a [2] 0c 51 [2] 03 4b [2] 1d 56 [2] 1f 57 [2] 04 51 [2] 18 56 [2] 04 79 }

  condition:
    any of them
}