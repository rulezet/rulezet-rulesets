rule TTP_XOR_MULT_DOSStub_4a57 {
  strings:
    $key_4a57 = { 1e 3f [2] 6a 27 [2] 2d 25 [2] 6a 34 [2] 24 38 [2] 28 32 [2] 3f 39 [2] 24 77 [2] 19 }

  condition:
    any of them
}