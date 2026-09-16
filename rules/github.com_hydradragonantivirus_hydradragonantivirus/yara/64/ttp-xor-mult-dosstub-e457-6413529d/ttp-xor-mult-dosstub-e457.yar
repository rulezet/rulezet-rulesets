rule TTP_XOR_MULT_DOSStub_e457 {
  strings:
    $key_e457 = { b0 3f [2] c4 27 [2] 83 25 [2] c4 34 [2] 8a 38 [2] 86 32 [2] 91 39 [2] 8a 77 [2] b7 }

  condition:
    any of them
}