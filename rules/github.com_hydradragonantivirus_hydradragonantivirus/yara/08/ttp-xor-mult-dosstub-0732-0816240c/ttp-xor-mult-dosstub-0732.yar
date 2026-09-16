rule TTP_XOR_MULT_DOSStub_0732 {
  strings:
    $key_0732 = { 53 5a [2] 27 42 [2] 60 40 [2] 27 51 [2] 69 5d [2] 65 57 [2] 72 5c [2] 69 12 [2] 54 }

  condition:
    any of them
}