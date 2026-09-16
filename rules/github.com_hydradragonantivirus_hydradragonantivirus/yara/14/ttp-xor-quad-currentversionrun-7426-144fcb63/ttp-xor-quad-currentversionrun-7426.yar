rule TTP_XOR_QUAD_CurrentVersionRun_7426 {
  strings:
    $key_7426 = { 27 49 [2] 03 47 [2] 28 6b [2] 06 49 [2] 12 52 [2] 1d 48 [2] 03 55 [2] 01 54 [2] 1a 52 [2] 06 55 [2] 1a 7a }

  condition:
    any of them
}