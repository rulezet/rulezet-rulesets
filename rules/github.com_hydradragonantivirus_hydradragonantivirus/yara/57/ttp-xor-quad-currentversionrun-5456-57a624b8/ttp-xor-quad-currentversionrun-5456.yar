rule TTP_XOR_QUAD_CurrentVersionRun_5456 {
  strings:
    $key_5456 = { 07 39 [2] 23 37 [2] 08 1b [2] 26 39 [2] 32 22 [2] 3d 38 [2] 23 25 [2] 21 24 [2] 3a 22 [2] 26 25 [2] 3a 0a }

  condition:
    any of them
}