rule TTP_XOR_MULT_DOSStub_5467 {
  strings:
    $key_5467 = { 00 0f [2] 74 17 [2] 33 15 [2] 74 04 [2] 3a 08 [2] 36 02 [2] 21 09 [2] 3a 47 [2] 07 }

  condition:
    any of them
}