rule TTP_XOR_MULT_DOSStub_c08d {
  strings:
    $key_c08d = { 94 e5 [2] e0 fd [2] a7 ff [2] e0 ee [2] ae e2 [2] a2 e8 [2] b5 e3 [2] ae ad [2] 93 }

  condition:
    any of them
}