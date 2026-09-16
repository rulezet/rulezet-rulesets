rule TTP_XOR_MULT_DOSStub_f73d {
  strings:
    $key_f73d = { a3 55 [2] d7 4d [2] 90 4f [2] d7 5e [2] 99 52 [2] 95 58 [2] 82 53 [2] 99 1d [2] a4 }

  condition:
    any of them
}