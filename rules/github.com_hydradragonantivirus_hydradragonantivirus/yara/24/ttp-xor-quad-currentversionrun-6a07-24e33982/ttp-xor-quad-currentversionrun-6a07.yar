rule TTP_XOR_QUAD_CurrentVersionRun_6a07 {
  strings:
    $key_6a07 = { 39 68 [2] 1d 66 [2] 36 4a [2] 18 68 [2] 0c 73 [2] 03 69 [2] 1d 74 [2] 1f 75 [2] 04 73 [2] 18 74 [2] 04 5b }

  condition:
    any of them
}