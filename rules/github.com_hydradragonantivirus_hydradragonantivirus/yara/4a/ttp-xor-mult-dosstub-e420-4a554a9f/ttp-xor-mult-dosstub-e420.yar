rule TTP_XOR_MULT_DOSStub_e420 {
  strings:
    $key_e420 = { b0 48 [2] c4 50 [2] 83 52 [2] c4 43 [2] 8a 4f [2] 86 45 [2] 91 4e [2] 8a 00 [2] b7 }

  condition:
    any of them
}