rule TTP_XOR_QUAD_CurrentVersionRun_7a04 {
  strings:
    $key_7a04 = { 29 6b [2] 0d 65 [2] 26 49 [2] 08 6b [2] 1c 70 [2] 13 6a [2] 0d 77 [2] 0f 76 [2] 14 70 [2] 08 77 [2] 14 58 }

  condition:
    any of them
}