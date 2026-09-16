rule TTP_XOR_QUAD_CurrentVersionRun_0a7b {
  strings:
    $key_0a7b = { 59 14 [2] 7d 1a [2] 56 36 [2] 78 14 [2] 6c 0f [2] 63 15 [2] 7d 08 [2] 7f 09 [2] 64 0f [2] 78 08 [2] 64 27 }

  condition:
    any of them
}