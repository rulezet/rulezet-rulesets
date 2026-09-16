rule TTP_XOR_MULT_DOSStub_8bb7 {
  strings:
    $key_8bb7 = { df df [2] ab c7 [2] ec c5 [2] ab d4 [2] e5 d8 [2] e9 d2 [2] fe d9 [2] e5 97 [2] d8 }

  condition:
    any of them
}