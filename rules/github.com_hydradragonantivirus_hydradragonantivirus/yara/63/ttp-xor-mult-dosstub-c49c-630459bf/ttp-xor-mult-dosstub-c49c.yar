rule TTP_XOR_MULT_DOSStub_c49c {
  strings:
    $key_c49c = { 90 f4 [2] e4 ec [2] a3 ee [2] e4 ff [2] aa f3 [2] a6 f9 [2] b1 f2 [2] aa bc [2] 97 }

  condition:
    any of them
}