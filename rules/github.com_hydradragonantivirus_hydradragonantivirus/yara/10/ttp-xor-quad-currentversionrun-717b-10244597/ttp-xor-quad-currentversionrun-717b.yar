rule TTP_XOR_QUAD_CurrentVersionRun_717b {
  strings:
    $key_717b = { 22 14 [2] 06 1a [2] 2d 36 [2] 03 14 [2] 17 0f [2] 18 15 [2] 06 08 [2] 04 09 [2] 1f 0f [2] 03 08 [2] 1f 27 }

  condition:
    any of them
}