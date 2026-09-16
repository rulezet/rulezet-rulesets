rule TTP_XOR_MULT_DOSStub_f7fc {
  strings:
    $key_f7fc = { a3 94 [2] d7 8c [2] 90 8e [2] d7 9f [2] 99 93 [2] 95 99 [2] 82 92 [2] 99 dc [2] a4 }

  condition:
    any of them
}