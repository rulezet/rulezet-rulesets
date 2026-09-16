rule TTP_XOR_MULT_DOSStub_f6c7 {
  strings:
    $key_f6c7 = { a2 af [2] d6 b7 [2] 91 b5 [2] d6 a4 [2] 98 a8 [2] 94 a2 [2] 83 a9 [2] 98 e7 [2] a5 }

  condition:
    any of them
}