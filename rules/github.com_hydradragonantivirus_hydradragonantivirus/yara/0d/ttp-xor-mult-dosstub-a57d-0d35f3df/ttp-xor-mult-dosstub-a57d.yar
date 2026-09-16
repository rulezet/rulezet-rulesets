rule TTP_XOR_MULT_DOSStub_a57d {
  strings:
    $key_a57d = { f1 15 [2] 85 0d [2] c2 0f [2] 85 1e [2] cb 12 [2] c7 18 [2] d0 13 [2] cb 5d [2] f6 }

  condition:
    any of them
}