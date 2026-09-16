rule TTP_XOR_MULT_DOSStub_6063 {
  strings:
    $key_6063 = { 34 0b [2] 40 13 [2] 07 11 [2] 40 00 [2] 0e 0c [2] 02 06 [2] 15 0d [2] 0e 43 [2] 33 }

  condition:
    any of them
}