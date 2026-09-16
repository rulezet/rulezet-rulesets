rule TTP_XOR_MULT_DOSStub_f0ca {
  strings:
    $key_f0ca = { a4 a2 [2] d0 ba [2] 97 b8 [2] d0 a9 [2] 9e a5 [2] 92 af [2] 85 a4 [2] 9e ea [2] a3 }

  condition:
    any of them
}