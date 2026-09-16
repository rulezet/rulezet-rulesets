rule TTP_XOR_MULT_DOSStub_c9b7 {
  strings:
    $key_c9b7 = { 9d df [2] e9 c7 [2] ae c5 [2] e9 d4 [2] a7 d8 [2] ab d2 [2] bc d9 [2] a7 97 [2] 9a }

  condition:
    any of them
}