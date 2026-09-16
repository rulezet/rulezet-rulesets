rule TTP_XOR_MULT_DOSStub_f77d {
  strings:
    $key_f77d = { a3 15 [2] d7 0d [2] 90 0f [2] d7 1e [2] 99 12 [2] 95 18 [2] 82 13 [2] 99 5d [2] a4 }

  condition:
    any of them
}