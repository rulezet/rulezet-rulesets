rule TTP_XOR_QUAD_CurrentVersionRun_7a6b {
  strings:
    $key_7a6b = { 29 04 [2] 0d 0a [2] 26 26 [2] 08 04 [2] 1c 1f [2] 13 05 [2] 0d 18 [2] 0f 19 [2] 14 1f [2] 08 18 [2] 14 37 }

  condition:
    any of them
}