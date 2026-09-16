rule TTP_XOR_MULT_DOSStub_f27f {
  strings:
    $key_f27f = { a6 17 [2] d2 0f [2] 95 0d [2] d2 1c [2] 9c 10 [2] 90 1a [2] 87 11 [2] 9c 5f [2] a1 }

  condition:
    any of them
}