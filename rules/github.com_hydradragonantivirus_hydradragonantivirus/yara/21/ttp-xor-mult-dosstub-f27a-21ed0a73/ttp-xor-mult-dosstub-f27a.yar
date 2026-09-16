rule TTP_XOR_MULT_DOSStub_f27a {
  strings:
    $key_f27a = { a6 12 [2] d2 0a [2] 95 08 [2] d2 19 [2] 9c 15 [2] 90 1f [2] 87 14 [2] 9c 5a [2] a1 }

  condition:
    any of them
}