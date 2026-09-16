rule TTP_XOR_MULT_DOSStub_f1fc {
  strings:
    $key_f1fc = { a5 94 [2] d1 8c [2] 96 8e [2] d1 9f [2] 9f 93 [2] 93 99 [2] 84 92 [2] 9f dc [2] a2 }

  condition:
    any of them
}