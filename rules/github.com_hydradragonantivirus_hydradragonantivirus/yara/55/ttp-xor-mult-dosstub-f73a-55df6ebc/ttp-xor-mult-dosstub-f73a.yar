rule TTP_XOR_MULT_DOSStub_f73a {
  strings:
    $key_f73a = { a3 52 [2] d7 4a [2] 90 48 [2] d7 59 [2] 99 55 [2] 95 5f [2] 82 54 [2] 99 1a [2] a4 }

  condition:
    any of them
}