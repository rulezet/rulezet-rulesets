rule TTP_XOR_MULT_DOSStub_f72c {
  strings:
    $key_f72c = { a3 44 [2] d7 5c [2] 90 5e [2] d7 4f [2] 99 43 [2] 95 49 [2] 82 42 [2] 99 0c [2] a4 }

  condition:
    any of them
}