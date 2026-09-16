rule TTP_XOR_QUAD_CurrentVersionRun_6a66 {
  strings:
    $key_6a66 = { 39 09 [2] 1d 07 [2] 36 2b [2] 18 09 [2] 0c 12 [2] 03 08 [2] 1d 15 [2] 1f 14 [2] 04 12 [2] 18 15 [2] 04 3a }

  condition:
    any of them
}