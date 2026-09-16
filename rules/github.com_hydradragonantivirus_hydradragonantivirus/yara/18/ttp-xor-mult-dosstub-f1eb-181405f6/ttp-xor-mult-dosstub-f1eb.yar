rule TTP_XOR_MULT_DOSStub_f1eb {
  strings:
    $key_f1eb = { a5 83 [2] d1 9b [2] 96 99 [2] d1 88 [2] 9f 84 [2] 93 8e [2] 84 85 [2] 9f cb [2] a2 }

  condition:
    any of them
}