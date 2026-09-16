rule TTP_XOR_MULT_DOSStub_f7e1 {
  strings:
    $key_f7e1 = { a3 89 [2] d7 91 [2] 90 93 [2] d7 82 [2] 99 8e [2] 95 84 [2] 82 8f [2] 99 c1 [2] a4 }

  condition:
    any of them
}