rule TTP_XOR_MULT_DOSStub_e407 {
  strings:
    $key_e407 = { b0 6f [2] c4 77 [2] 83 75 [2] c4 64 [2] 8a 68 [2] 86 62 [2] 91 69 [2] 8a 27 [2] b7 }

  condition:
    any of them
}