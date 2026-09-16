rule TTP_XOR_MULT_DOSStub_f091 {
  strings:
    $key_f091 = { a4 f9 [2] d0 e1 [2] 97 e3 [2] d0 f2 [2] 9e fe [2] 92 f4 [2] 85 ff [2] 9e b1 [2] a3 }

  condition:
    any of them
}