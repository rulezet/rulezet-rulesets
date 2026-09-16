rule TTP_XOR_MULT_DOSStub_5421 {
  strings:
    $key_5421 = { 00 49 [2] 74 51 [2] 33 53 [2] 74 42 [2] 3a 4e [2] 36 44 [2] 21 4f [2] 3a 01 [2] 07 }

  condition:
    any of them
}