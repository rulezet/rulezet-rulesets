rule TTP_XOR_MULT_DOSStub_9215 {
  strings:
    $key_9215 = { c6 7d [2] b2 65 [2] f5 67 [2] b2 76 [2] fc 7a [2] f0 70 [2] e7 7b [2] fc 35 [2] c1 }

  condition:
    any of them
}