rule TTP_XOR_MULT_DOSStub_f197 {
  strings:
    $key_f197 = { a5 ff [2] d1 e7 [2] 96 e5 [2] d1 f4 [2] 9f f8 [2] 93 f2 [2] 84 f9 [2] 9f b7 [2] a2 }

  condition:
    any of them
}