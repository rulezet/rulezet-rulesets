rule TTP_XOR_MULT_DOSStub_a57c {
  strings:
    $key_a57c = { f1 14 [2] 85 0c [2] c2 0e [2] 85 1f [2] cb 13 [2] c7 19 [2] d0 12 [2] cb 5c [2] f6 }

  condition:
    any of them
}