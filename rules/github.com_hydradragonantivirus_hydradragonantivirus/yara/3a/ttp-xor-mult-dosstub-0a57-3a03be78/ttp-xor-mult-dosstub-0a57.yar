rule TTP_XOR_MULT_DOSStub_0a57 {
  strings:
    $key_0a57 = { 5e 3f [2] 2a 27 [2] 6d 25 [2] 2a 34 [2] 64 38 [2] 68 32 [2] 7f 39 [2] 64 77 [2] 59 }

  condition:
    any of them
}