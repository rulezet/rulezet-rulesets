rule TTP_XOR_QUAD_CurrentVersionRun_a57f {
  strings:
    $key_a57f = { f6 10 [2] d2 1e [2] f9 32 [2] d7 10 [2] c3 0b [2] cc 11 [2] d2 0c [2] d0 0d [2] cb 0b [2] d7 0c [2] cb 23 }

  condition:
    any of them
}