rule TTP_XOR_QUAD_CurrentVersionRun_7a0b {
  strings:
    $key_7a0b = { 29 64 [2] 0d 6a [2] 26 46 [2] 08 64 [2] 1c 7f [2] 13 65 [2] 0d 78 [2] 0f 79 [2] 14 7f [2] 08 78 [2] 14 57 }

  condition:
    any of them
}