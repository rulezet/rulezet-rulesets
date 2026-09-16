rule TTP_XOR_MULT_DOSStub_8a80 {
  strings:
    $key_8a80 = { de e8 [2] aa f0 [2] ed f2 [2] aa e3 [2] e4 ef [2] e8 e5 [2] ff ee [2] e4 a0 [2] d9 }

  condition:
    any of them
}