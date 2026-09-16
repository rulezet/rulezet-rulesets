rule TTP_XOR_MULT_DOSStub_e4e6 {
  strings:
    $key_e4e6 = { b0 8e [2] c4 96 [2] 83 94 [2] c4 85 [2] 8a 89 [2] 86 83 [2] 91 88 [2] 8a c6 [2] b7 }

  condition:
    any of them
}