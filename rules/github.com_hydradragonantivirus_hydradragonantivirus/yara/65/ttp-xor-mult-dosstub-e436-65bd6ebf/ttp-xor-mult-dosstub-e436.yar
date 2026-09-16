rule TTP_XOR_MULT_DOSStub_e436 {
  strings:
    $key_e436 = { b0 5e [2] c4 46 [2] 83 44 [2] c4 55 [2] 8a 59 [2] 86 53 [2] 91 58 [2] 8a 16 [2] b7 }

  condition:
    any of them
}