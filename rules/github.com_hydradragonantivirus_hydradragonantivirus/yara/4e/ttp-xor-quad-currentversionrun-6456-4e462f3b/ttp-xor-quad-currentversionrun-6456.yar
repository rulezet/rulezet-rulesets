rule TTP_XOR_QUAD_CurrentVersionRun_6456 {
  strings:
    $key_6456 = { 37 39 [2] 13 37 [2] 38 1b [2] 16 39 [2] 02 22 [2] 0d 38 [2] 13 25 [2] 11 24 [2] 0a 22 [2] 16 25 [2] 0a 0a }

  condition:
    any of them
}