rule TTP_XOR_MULT_DOSStub_f27c {
  strings:
    $key_f27c = { a6 14 [2] d2 0c [2] 95 0e [2] d2 1f [2] 9c 13 [2] 90 19 [2] 87 12 [2] 9c 5c [2] a1 }

  condition:
    any of them
}