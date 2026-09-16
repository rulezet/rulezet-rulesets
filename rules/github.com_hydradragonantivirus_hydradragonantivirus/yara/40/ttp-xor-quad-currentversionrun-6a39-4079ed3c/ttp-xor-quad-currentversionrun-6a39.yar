rule TTP_XOR_QUAD_CurrentVersionRun_6a39 {
  strings:
    $key_6a39 = { 39 56 [2] 1d 58 [2] 36 74 [2] 18 56 [2] 0c 4d [2] 03 57 [2] 1d 4a [2] 1f 4b [2] 04 4d [2] 18 4a [2] 04 65 }

  condition:
    any of them
}