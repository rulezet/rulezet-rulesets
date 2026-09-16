rule TTP_XOR_MULT_DOSStub_a57f {
  strings:
    $key_a57f = { f1 17 [2] 85 0f [2] c2 0d [2] 85 1c [2] cb 10 [2] c7 1a [2] d0 11 [2] cb 5f [2] f6 }

  condition:
    any of them
}