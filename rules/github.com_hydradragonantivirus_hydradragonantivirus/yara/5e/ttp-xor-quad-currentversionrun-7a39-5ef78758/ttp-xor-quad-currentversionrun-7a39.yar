rule TTP_XOR_QUAD_CurrentVersionRun_7a39 {
  strings:
    $key_7a39 = { 29 56 [2] 0d 58 [2] 26 74 [2] 08 56 [2] 1c 4d [2] 13 57 [2] 0d 4a [2] 0f 4b [2] 14 4d [2] 08 4a [2] 14 65 }

  condition:
    any of them
}