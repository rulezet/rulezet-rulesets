rule TTP_XOR_MULT_DOSStub_0132 {
  strings:
    $key_0132 = { 55 5a [2] 21 42 [2] 66 40 [2] 21 51 [2] 6f 5d [2] 63 57 [2] 74 5c [2] 6f 12 [2] 52 }

  condition:
    any of them
}