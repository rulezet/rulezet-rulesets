rule TTP_XOR_MULT_DOSStub_f265 {
  strings:
    $key_f265 = { a6 0d [2] d2 15 [2] 95 17 [2] d2 06 [2] 9c 0a [2] 90 00 [2] 87 0b [2] 9c 45 [2] a1 }

  condition:
    any of them
}