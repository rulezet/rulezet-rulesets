rule TTP_XOR_QUAD_CurrentVersionRun_687d {
  strings:
    $key_687d = { 3b 12 [2] 1f 1c [2] 34 30 [2] 1a 12 [2] 0e 09 [2] 01 13 [2] 1f 0e [2] 1d 0f [2] 06 09 [2] 1a 0e [2] 06 21 }

  condition:
    any of them
}