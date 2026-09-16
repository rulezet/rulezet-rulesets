rule TTP_XOR_QUAD_CurrentVersionRun_6a1b {
  strings:
    $key_6a1b = { 39 74 [2] 1d 7a [2] 36 56 [2] 18 74 [2] 0c 6f [2] 03 75 [2] 1d 68 [2] 1f 69 [2] 04 6f [2] 18 68 [2] 04 47 }

  condition:
    any of them
}