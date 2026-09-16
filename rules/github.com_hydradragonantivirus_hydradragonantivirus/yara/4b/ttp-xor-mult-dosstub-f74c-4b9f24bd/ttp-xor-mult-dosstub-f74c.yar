rule TTP_XOR_MULT_DOSStub_f74c {
  strings:
    $key_f74c = { a3 24 [2] d7 3c [2] 90 3e [2] d7 2f [2] 99 23 [2] 95 29 [2] 82 22 [2] 99 6c [2] a4 }

  condition:
    any of them
}