rule TTP_XOR_MULT_DOSStub_8e96 {
  strings:
    $key_8e96 = { da fe [2] ae e6 [2] e9 e4 [2] ae f5 [2] e0 f9 [2] ec f3 [2] fb f8 [2] e0 b6 [2] dd }

  condition:
    any of them
}