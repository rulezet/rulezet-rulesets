rule TTP_XOR_QUAD_CurrentVersionRun_0a58 {
  strings:
    $key_0a58 = { 59 37 [2] 7d 39 [2] 56 15 [2] 78 37 [2] 6c 2c [2] 63 36 [2] 7d 2b [2] 7f 2a [2] 64 2c [2] 78 2b [2] 64 04 }

  condition:
    any of them
}