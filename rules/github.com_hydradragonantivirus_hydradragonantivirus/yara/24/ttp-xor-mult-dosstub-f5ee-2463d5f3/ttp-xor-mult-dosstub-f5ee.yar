rule TTP_XOR_MULT_DOSStub_f5ee {
  strings:
    $key_f5ee = { a1 86 [2] d5 9e [2] 92 9c [2] d5 8d [2] 9b 81 [2] 97 8b [2] 80 80 [2] 9b ce [2] a6 }

  condition:
    any of them
}