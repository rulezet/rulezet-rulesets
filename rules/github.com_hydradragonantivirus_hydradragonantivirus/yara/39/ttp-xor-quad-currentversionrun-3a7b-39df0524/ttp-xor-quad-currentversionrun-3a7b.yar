rule TTP_XOR_QUAD_CurrentVersionRun_3a7b {
  strings:
    $key_3a7b = { 69 14 [2] 4d 1a [2] 66 36 [2] 48 14 [2] 5c 0f [2] 53 15 [2] 4d 08 [2] 4f 09 [2] 54 0f [2] 48 08 [2] 54 27 }

  condition:
    any of them
}