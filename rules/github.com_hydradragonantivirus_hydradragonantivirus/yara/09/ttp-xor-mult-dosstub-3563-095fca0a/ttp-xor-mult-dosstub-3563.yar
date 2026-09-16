rule TTP_XOR_MULT_DOSStub_3563 {
  strings:
    $key_3563 = { 61 0b [2] 15 13 [2] 52 11 [2] 15 00 [2] 5b 0c [2] 57 06 [2] 40 0d [2] 5b 43 [2] 66 }

  condition:
    any of them
}