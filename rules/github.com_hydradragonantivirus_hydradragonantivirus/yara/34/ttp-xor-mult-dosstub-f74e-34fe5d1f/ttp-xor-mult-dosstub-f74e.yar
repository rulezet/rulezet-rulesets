rule TTP_XOR_MULT_DOSStub_f74e {
  strings:
    $key_f74e = { a3 26 [2] d7 3e [2] 90 3c [2] d7 2d [2] 99 21 [2] 95 2b [2] 82 20 [2] 99 6e [2] a4 }

  condition:
    any of them
}