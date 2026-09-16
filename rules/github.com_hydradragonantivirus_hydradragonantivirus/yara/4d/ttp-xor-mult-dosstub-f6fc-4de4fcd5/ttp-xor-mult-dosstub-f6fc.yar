rule TTP_XOR_MULT_DOSStub_f6fc {
  strings:
    $key_f6fc = { a2 94 [2] d6 8c [2] 91 8e [2] d6 9f [2] 98 93 [2] 94 99 [2] 83 92 [2] 98 dc [2] a5 }

  condition:
    any of them
}