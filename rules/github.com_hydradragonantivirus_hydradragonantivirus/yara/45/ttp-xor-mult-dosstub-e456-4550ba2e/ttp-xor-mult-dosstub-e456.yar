rule TTP_XOR_MULT_DOSStub_e456 {
  strings:
    $key_e456 = { b0 3e [2] c4 26 [2] 83 24 [2] c4 35 [2] 8a 39 [2] 86 33 [2] 91 38 [2] 8a 76 [2] b7 }

  condition:
    any of them
}