rule TTP_XOR_MULT_DOSStub_3679 {
  strings:
    $key_3679 = { 62 11 [2] 16 09 [2] 51 0b [2] 16 1a [2] 58 16 [2] 54 1c [2] 43 17 [2] 58 59 [2] 65 }

  condition:
    any of them
}