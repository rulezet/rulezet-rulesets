rule TTP_XOR_MULT_DOSStub_5a57 {
  strings:
    $key_5a57 = { 0e 3f [2] 7a 27 [2] 3d 25 [2] 7a 34 [2] 34 38 [2] 38 32 [2] 2f 39 [2] 34 77 [2] 09 }

  condition:
    any of them
}