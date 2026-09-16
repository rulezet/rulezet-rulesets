rule TTP_XOR_MULT_DOSStub_f1f6 {
  strings:
    $key_f1f6 = { a5 9e [2] d1 86 [2] 96 84 [2] d1 95 [2] 9f 99 [2] 93 93 [2] 84 98 [2] 9f d6 [2] a2 }

  condition:
    any of them
}