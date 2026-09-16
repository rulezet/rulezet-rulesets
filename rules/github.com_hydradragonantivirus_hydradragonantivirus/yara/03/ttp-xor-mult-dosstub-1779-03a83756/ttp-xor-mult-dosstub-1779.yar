rule TTP_XOR_MULT_DOSStub_1779 {
  strings:
    $key_1779 = { 43 11 [2] 37 09 [2] 70 0b [2] 37 1a [2] 79 16 [2] 75 1c [2] 62 17 [2] 79 59 [2] 44 }

  condition:
    any of them
}