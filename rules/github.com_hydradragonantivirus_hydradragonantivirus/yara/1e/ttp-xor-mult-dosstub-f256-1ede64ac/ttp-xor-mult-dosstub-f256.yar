rule TTP_XOR_MULT_DOSStub_f256 {
  strings:
    $key_f256 = { a6 3e [2] d2 26 [2] 95 24 [2] d2 35 [2] 9c 39 [2] 90 33 [2] 87 38 [2] 9c 76 [2] a1 }

  condition:
    any of them
}