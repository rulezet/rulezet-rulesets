rule TTP_XOR_MULT_DOSStub_6011 {
  strings:
    $key_6011 = { 34 79 [2] 40 61 [2] 07 63 [2] 40 72 [2] 0e 7e [2] 02 74 [2] 15 7f [2] 0e 31 [2] 33 }

  condition:
    any of them
}