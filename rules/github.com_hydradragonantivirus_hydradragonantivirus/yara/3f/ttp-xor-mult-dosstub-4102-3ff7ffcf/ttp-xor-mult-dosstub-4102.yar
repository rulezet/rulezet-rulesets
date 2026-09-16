rule TTP_XOR_MULT_DOSStub_4102 {
  strings:
    $key_4102 = { 15 6a [2] 61 72 [2] 26 70 [2] 61 61 [2] 2f 6d [2] 23 67 [2] 34 6c [2] 2f 22 [2] 12 }

  condition:
    any of them
}