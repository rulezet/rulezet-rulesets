rule TTP_XOR_MULT_DOSStub_f17c {
  strings:
    $key_f17c = { a5 14 [2] d1 0c [2] 96 0e [2] d1 1f [2] 9f 13 [2] 93 19 [2] 84 12 [2] 9f 5c [2] a2 }

  condition:
    any of them
}