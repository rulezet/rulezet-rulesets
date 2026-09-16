rule TTP_XOR_QUAD_CurrentVersionRun_546b {
  strings:
    $key_546b = { 07 04 [2] 23 0a [2] 08 26 [2] 26 04 [2] 32 1f [2] 3d 05 [2] 23 18 [2] 21 19 [2] 3a 1f [2] 26 18 [2] 3a 37 }

  condition:
    any of them
}