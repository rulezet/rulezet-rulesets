rule TTP_XOR_MULT_DOSStub_f0ee {
  strings:
    $key_f0ee = { a4 86 [2] d0 9e [2] 97 9c [2] d0 8d [2] 9e 81 [2] 92 8b [2] 85 80 [2] 9e ce [2] a3 }

  condition:
    any of them
}