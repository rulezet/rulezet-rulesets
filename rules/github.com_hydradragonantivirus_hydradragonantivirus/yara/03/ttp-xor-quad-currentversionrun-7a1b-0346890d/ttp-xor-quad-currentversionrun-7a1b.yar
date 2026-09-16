rule TTP_XOR_QUAD_CurrentVersionRun_7a1b {
  strings:
    $key_7a1b = { 29 74 [2] 0d 7a [2] 26 56 [2] 08 74 [2] 1c 6f [2] 13 75 [2] 0d 68 [2] 0f 69 [2] 14 6f [2] 08 68 [2] 14 47 }

  condition:
    any of them
}