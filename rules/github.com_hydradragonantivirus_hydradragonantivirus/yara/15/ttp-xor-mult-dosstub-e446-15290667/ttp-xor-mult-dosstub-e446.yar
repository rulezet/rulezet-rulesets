rule TTP_XOR_MULT_DOSStub_e446 {
  strings:
    $key_e446 = { b0 2e [2] c4 36 [2] 83 34 [2] c4 25 [2] 8a 29 [2] 86 23 [2] 91 28 [2] 8a 66 [2] b7 }

  condition:
    any of them
}