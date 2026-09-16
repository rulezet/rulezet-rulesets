rule TTP_XOR_MULT_DOSStub_d993 {
  strings:
    $key_d993 = { 8d fb [2] f9 e3 [2] be e1 [2] f9 f0 [2] b7 fc [2] bb f6 [2] ac fd [2] b7 b3 [2] 8a }

  condition:
    any of them
}