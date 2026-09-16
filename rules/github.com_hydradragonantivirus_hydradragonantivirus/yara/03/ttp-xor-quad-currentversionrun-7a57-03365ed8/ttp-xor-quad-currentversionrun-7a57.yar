rule TTP_XOR_QUAD_CurrentVersionRun_7a57 {
  strings:
    $key_7a57 = { 29 38 [2] 0d 36 [2] 26 1a [2] 08 38 [2] 1c 23 [2] 13 39 [2] 0d 24 [2] 0f 25 [2] 14 23 [2] 08 24 [2] 14 0b }

  condition:
    any of them
}