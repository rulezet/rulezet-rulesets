rule TTP_XOR_MULT_DOSStub_f6f1 {
  strings:
    $key_f6f1 = { a2 99 [2] d6 81 [2] 91 83 [2] d6 92 [2] 98 9e [2] 94 94 [2] 83 9f [2] 98 d1 [2] a5 }

  condition:
    any of them
}