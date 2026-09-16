rule TTP_XOR_QUAD_CurrentVersionRun_6a58 {
  strings:
    $key_6a58 = { 39 37 [2] 1d 39 [2] 36 15 [2] 18 37 [2] 0c 2c [2] 03 36 [2] 1d 2b [2] 1f 2a [2] 04 2c [2] 18 2b [2] 04 04 }

  condition:
    any of them
}