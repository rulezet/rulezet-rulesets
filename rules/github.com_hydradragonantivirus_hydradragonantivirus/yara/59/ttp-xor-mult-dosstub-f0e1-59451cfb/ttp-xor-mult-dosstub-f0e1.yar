rule TTP_XOR_MULT_DOSStub_f0e1 {
  strings:
    $key_f0e1 = { a4 89 [2] d0 91 [2] 97 93 [2] d0 82 [2] 9e 8e [2] 92 84 [2] 85 8f [2] 9e c1 [2] a3 }

  condition:
    any of them
}