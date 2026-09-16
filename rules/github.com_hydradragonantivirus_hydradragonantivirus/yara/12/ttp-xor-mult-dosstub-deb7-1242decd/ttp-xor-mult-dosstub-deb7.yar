rule TTP_XOR_MULT_DOSStub_deb7 {
  strings:
    $key_deb7 = { 8a df [2] fe c7 [2] b9 c5 [2] fe d4 [2] b0 d8 [2] bc d2 [2] ab d9 [2] b0 97 [2] 8d }

  condition:
    any of them
}