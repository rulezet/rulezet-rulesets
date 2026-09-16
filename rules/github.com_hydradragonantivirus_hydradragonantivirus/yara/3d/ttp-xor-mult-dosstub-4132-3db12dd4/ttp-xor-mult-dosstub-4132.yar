rule TTP_XOR_MULT_DOSStub_4132 {
  strings:
    $key_4132 = { 15 5a [2] 61 42 [2] 26 40 [2] 61 51 [2] 2f 5d [2] 23 57 [2] 34 5c [2] 2f 12 [2] 12 }

  condition:
    any of them
}