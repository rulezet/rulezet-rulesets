rule TTP_XOR_MULT_DOSStub_5411 {
  strings:
    $key_5411 = { 00 79 [2] 74 61 [2] 33 63 [2] 74 72 [2] 3a 7e [2] 36 74 [2] 21 7f [2] 3a 31 [2] 07 }

  condition:
    any of them
}