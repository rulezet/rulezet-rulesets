rule TTP_XOR_MULT_DOSStub_f249 {
  strings:
    $key_f249 = { a6 21 [2] d2 39 [2] 95 3b [2] d2 2a [2] 9c 26 [2] 90 2c [2] 87 27 [2] 9c 69 [2] a1 }

  condition:
    any of them
}