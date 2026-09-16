rule TTP_XOR_QUAD_CurrentVersionRun_687a {
  strings:
    $key_687a = { 3b 15 [2] 1f 1b [2] 34 37 [2] 1a 15 [2] 0e 0e [2] 01 14 [2] 1f 09 [2] 1d 08 [2] 06 0e [2] 1a 09 [2] 06 26 }

  condition:
    any of them
}