rule TTP_XOR_QUAD_CurrentVersionRun_6a77 {
  strings:
    $key_6a77 = { 39 18 [2] 1d 16 [2] 36 3a [2] 18 18 [2] 0c 03 [2] 03 19 [2] 1d 04 [2] 1f 05 [2] 04 03 [2] 18 04 [2] 04 2b }

  condition:
    any of them
}