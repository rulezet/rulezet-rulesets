rule TTP_XOR_QUAD_CurrentVersionRun_6545 {
  strings:
    $key_6545 = { 36 2a [2] 12 24 [2] 39 08 [2] 17 2a [2] 03 31 [2] 0c 2b [2] 12 36 [2] 10 37 [2] 0b 31 [2] 17 36 [2] 0b 19 }

  condition:
    any of them
}