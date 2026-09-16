rule TTP_XOR_QUAD_CurrentVersionRun_5f26 {
  strings:
    $key_5f26 = { 0c 49 [2] 28 47 [2] 03 6b [2] 2d 49 [2] 39 52 [2] 36 48 [2] 28 55 [2] 2a 54 [2] 31 52 [2] 2d 55 [2] 31 7a }

  condition:
    any of them
}