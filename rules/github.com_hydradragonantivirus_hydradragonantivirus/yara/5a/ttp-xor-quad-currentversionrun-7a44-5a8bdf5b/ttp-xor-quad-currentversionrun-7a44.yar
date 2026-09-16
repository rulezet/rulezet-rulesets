rule TTP_XOR_QUAD_CurrentVersionRun_7a44 {
  strings:
    $key_7a44 = { 29 2b [2] 0d 25 [2] 26 09 [2] 08 2b [2] 1c 30 [2] 13 2a [2] 0d 37 [2] 0f 36 [2] 14 30 [2] 08 37 [2] 14 18 }

  condition:
    any of them
}