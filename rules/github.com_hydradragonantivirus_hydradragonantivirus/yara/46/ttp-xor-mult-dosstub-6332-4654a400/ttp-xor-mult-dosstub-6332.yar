rule TTP_XOR_MULT_DOSStub_6332 {
  strings:
    $key_6332 = { 37 5a [2] 43 42 [2] 04 40 [2] 43 51 [2] 0d 5d [2] 01 57 [2] 16 5c [2] 0d 12 [2] 30 }

  condition:
    any of them
}