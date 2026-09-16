rule TTP_XOR_QUAD_CurrentVersionRun_687c {
  strings:
    $key_687c = { 3b 13 [2] 1f 1d [2] 34 31 [2] 1a 13 [2] 0e 08 [2] 01 12 [2] 1f 0f [2] 1d 0e [2] 06 08 [2] 1a 0f [2] 06 20 }

  condition:
    any of them
}