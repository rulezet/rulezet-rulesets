rule TTP_XOR_QUAD_CurrentVersionRun_7307 {
  strings:
    $key_7307 = { 20 68 [2] 04 66 [2] 2f 4a [2] 01 68 [2] 15 73 [2] 1a 69 [2] 04 74 [2] 06 75 [2] 1d 73 [2] 01 74 [2] 1d 5b }

  condition:
    any of them
}