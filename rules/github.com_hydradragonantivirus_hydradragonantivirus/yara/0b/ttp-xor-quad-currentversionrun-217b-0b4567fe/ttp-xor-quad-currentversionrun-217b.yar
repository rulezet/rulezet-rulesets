rule TTP_XOR_QUAD_CurrentVersionRun_217b {
  strings:
    $key_217b = { 72 14 [2] 56 1a [2] 7d 36 [2] 53 14 [2] 47 0f [2] 48 15 [2] 56 08 [2] 54 09 [2] 4f 0f [2] 53 08 [2] 4f 27 }

  condition:
    any of them
}