rule TTP_XOR_MULT_DOSStub_f17b {
  strings:
    $key_f17b = { a5 13 [2] d1 0b [2] 96 09 [2] d1 18 [2] 9f 14 [2] 93 1e [2] 84 15 [2] 9f 5b [2] a2 }

  condition:
    any of them
}