rule TTP_XOR_QUAD_CurrentVersionRun_4341 {
  strings:
    $key_4341 = { 10 2e [2] 34 20 [2] 1f 0c [2] 31 2e [2] 25 35 [2] 2a 2f [2] 34 32 [2] 36 33 [2] 2d 35 [2] 31 32 [2] 2d 1d }

  condition:
    any of them
}