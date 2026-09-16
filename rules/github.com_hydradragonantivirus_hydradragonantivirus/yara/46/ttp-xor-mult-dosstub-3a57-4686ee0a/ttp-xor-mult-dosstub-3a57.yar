rule TTP_XOR_MULT_DOSStub_3a57 {
  strings:
    $key_3a57 = { 6e 3f [2] 1a 27 [2] 5d 25 [2] 1a 34 [2] 54 38 [2] 58 32 [2] 4f 39 [2] 54 77 [2] 69 }

  condition:
    any of them
}