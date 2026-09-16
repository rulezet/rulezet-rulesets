rule TTP_XOR_MULT_DOSStub_8ab5 {
  strings:
    $key_8ab5 = { de dd [2] aa c5 [2] ed c7 [2] aa d6 [2] e4 da [2] e8 d0 [2] ff db [2] e4 95 [2] d9 }

  condition:
    any of them
}