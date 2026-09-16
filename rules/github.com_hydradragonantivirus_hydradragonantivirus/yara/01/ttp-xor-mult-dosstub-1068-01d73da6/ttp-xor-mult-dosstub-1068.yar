rule TTP_XOR_MULT_DOSStub_1068 {
  strings:
    $key_1068 = { 44 00 [2] 30 18 [2] 77 1a [2] 30 0b [2] 7e 07 [2] 72 0d [2] 65 06 [2] 7e 48 [2] 43 }

  condition:
    any of them
}