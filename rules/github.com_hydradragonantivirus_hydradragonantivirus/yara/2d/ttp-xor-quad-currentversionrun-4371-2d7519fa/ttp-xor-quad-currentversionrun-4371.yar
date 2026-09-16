rule TTP_XOR_QUAD_CurrentVersionRun_4371 {
  strings:
    $key_4371 = { 10 1e [2] 34 10 [2] 1f 3c [2] 31 1e [2] 25 05 [2] 2a 1f [2] 34 02 [2] 36 03 [2] 2d 05 [2] 31 02 [2] 2d 2d }

  condition:
    any of them
}