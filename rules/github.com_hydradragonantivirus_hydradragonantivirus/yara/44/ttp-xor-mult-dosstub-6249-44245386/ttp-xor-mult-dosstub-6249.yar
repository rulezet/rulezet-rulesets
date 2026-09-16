rule TTP_XOR_MULT_DOSStub_6249 {
  strings:
    $key_6249 = { 36 21 [2] 42 39 [2] 05 3b [2] 42 2a [2] 0c 26 [2] 00 2c [2] 17 27 [2] 0c 69 [2] 31 }

  condition:
    any of them
}