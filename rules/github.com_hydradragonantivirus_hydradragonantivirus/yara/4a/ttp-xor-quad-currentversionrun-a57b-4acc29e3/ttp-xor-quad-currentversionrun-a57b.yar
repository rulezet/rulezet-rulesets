rule TTP_XOR_QUAD_CurrentVersionRun_a57b {
  strings:
    $key_a57b = { f6 14 [2] d2 1a [2] f9 36 [2] d7 14 [2] c3 0f [2] cc 15 [2] d2 08 [2] d0 09 [2] cb 0f [2] d7 08 [2] cb 27 }

  condition:
    any of them
}