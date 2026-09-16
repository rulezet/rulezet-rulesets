rule TTP_XOR_MULT_DOSStub_1563 {
  strings:
    $key_1563 = { 41 0b [2] 35 13 [2] 72 11 [2] 35 00 [2] 7b 0c [2] 77 06 [2] 60 0d [2] 7b 43 [2] 46 }

  condition:
    any of them
}