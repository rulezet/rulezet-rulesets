rule TTP_XOR_MULT_DOSStub_5663 {
  strings:
    $key_5663 = { 02 0b [2] 76 13 [2] 31 11 [2] 76 00 [2] 38 0c [2] 34 06 [2] 23 0d [2] 38 43 [2] 05 }

  condition:
    any of them
}