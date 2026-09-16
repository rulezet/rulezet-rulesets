rule TTP_XOR_MULT_DOSStub_e3e4 {
  strings:
    $key_e3e4 = { b7 8c [2] c3 94 [2] 84 96 [2] c3 87 [2] 8d 8b [2] 81 81 [2] 96 8a [2] 8d c4 [2] b0 }

  condition:
    any of them
}