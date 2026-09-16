rule TTP_XOR_QUAD_CurrentVersionRun_712c {
  strings:
    $key_712c = { 22 43 [2] 06 4d [2] 2d 61 [2] 03 43 [2] 17 58 [2] 18 42 [2] 06 5f [2] 04 5e [2] 1f 58 [2] 03 5f [2] 1f 70 }

  condition:
    any of them
}