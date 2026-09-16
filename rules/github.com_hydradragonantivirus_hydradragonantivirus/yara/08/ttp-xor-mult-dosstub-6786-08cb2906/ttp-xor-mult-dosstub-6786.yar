rule TTP_XOR_MULT_DOSStub_6786 {
  strings:
    $key_6786 = { 33 ee [2] 47 f6 [2] 00 f4 [2] 47 e5 [2] 09 e9 [2] 05 e3 [2] 12 e8 [2] 09 a6 [2] 34 }

  condition:
    any of them
}