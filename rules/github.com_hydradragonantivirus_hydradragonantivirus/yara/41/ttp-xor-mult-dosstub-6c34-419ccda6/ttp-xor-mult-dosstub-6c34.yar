rule TTP_XOR_MULT_DOSStub_6c34 {
  strings:
    $key_6c34 = { 38 5c [2] 4c 44 [2] 0b 46 [2] 4c 57 [2] 02 5b [2] 0e 51 [2] 19 5a [2] 02 14 [2] 3f }

  condition:
    any of them
}