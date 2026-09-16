rule TTP_XOR_QUAD_CurrentVersionRun_687b {
  strings:
    $key_687b = { 3b 14 [2] 1f 1a [2] 34 36 [2] 1a 14 [2] 0e 0f [2] 01 15 [2] 1f 08 [2] 1d 09 [2] 06 0f [2] 1a 08 [2] 06 27 }

  condition:
    any of them
}