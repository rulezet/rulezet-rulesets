rule TTP_XOR_QUAD_CurrentVersionRun_337b {
  strings:
    $key_337b = { 60 14 [2] 44 1a [2] 6f 36 [2] 41 14 [2] 55 0f [2] 5a 15 [2] 44 08 [2] 46 09 [2] 5d 0f [2] 41 08 [2] 5d 27 }

  condition:
    any of them
}