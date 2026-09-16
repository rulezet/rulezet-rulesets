rule TTP_XOR_MULT_DOSStub_f4e1 {
  strings:
    $key_f4e1 = { a0 89 [2] d4 91 [2] 93 93 [2] d4 82 [2] 9a 8e [2] 96 84 [2] 81 8f [2] 9a c1 [2] a7 }

  condition:
    any of them
}