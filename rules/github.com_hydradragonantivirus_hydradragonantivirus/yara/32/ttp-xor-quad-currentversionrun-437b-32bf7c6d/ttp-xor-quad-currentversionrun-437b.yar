rule TTP_XOR_QUAD_CurrentVersionRun_437b {
  strings:
    $key_437b = { 10 14 [2] 34 1a [2] 1f 36 [2] 31 14 [2] 25 0f [2] 2a 15 [2] 34 08 [2] 36 09 [2] 2d 0f [2] 31 08 [2] 2d 27 }

  condition:
    any of them
}