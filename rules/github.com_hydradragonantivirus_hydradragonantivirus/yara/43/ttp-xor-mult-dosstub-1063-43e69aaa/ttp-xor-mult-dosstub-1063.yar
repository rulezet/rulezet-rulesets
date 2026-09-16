rule TTP_XOR_MULT_DOSStub_1063 {
  strings:
    $key_1063 = { 44 0b [2] 30 13 [2] 77 11 [2] 30 00 [2] 7e 0c [2] 72 06 [2] 65 0d [2] 7e 43 [2] 43 }

  condition:
    any of them
}