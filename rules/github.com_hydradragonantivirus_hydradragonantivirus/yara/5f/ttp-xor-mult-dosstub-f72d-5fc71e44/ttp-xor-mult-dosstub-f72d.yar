rule TTP_XOR_MULT_DOSStub_f72d {
  strings:
    $key_f72d = { a3 45 [2] d7 5d [2] 90 5f [2] d7 4e [2] 99 42 [2] 95 48 [2] 82 43 [2] 99 0d [2] a4 }

  condition:
    any of them
}