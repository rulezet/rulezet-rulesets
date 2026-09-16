rule TTP_XOR_MULT_DOSStub_e431 {
  strings:
    $key_e431 = { b0 59 [2] c4 41 [2] 83 43 [2] c4 52 [2] 8a 5e [2] 86 54 [2] 91 5f [2] 8a 11 [2] b7 }

  condition:
    any of them
}