rule TTP_XOR_MULT_DOSStub_f201 {
  strings:
    $key_f201 = { a6 69 [2] d2 71 [2] 95 73 [2] d2 62 [2] 9c 6e [2] 90 64 [2] 87 6f [2] 9c 21 [2] a1 }

  condition:
    any of them
}