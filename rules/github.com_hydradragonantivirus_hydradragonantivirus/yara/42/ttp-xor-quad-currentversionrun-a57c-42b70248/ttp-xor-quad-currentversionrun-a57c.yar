rule TTP_XOR_QUAD_CurrentVersionRun_a57c {
  strings:
    $key_a57c = { f6 13 [2] d2 1d [2] f9 31 [2] d7 13 [2] c3 08 [2] cc 12 [2] d2 0f [2] d0 0e [2] cb 08 [2] d7 0f [2] cb 20 }

  condition:
    any of them
}