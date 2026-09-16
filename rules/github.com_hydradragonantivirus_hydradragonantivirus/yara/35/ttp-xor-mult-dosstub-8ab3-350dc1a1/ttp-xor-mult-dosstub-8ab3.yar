rule TTP_XOR_MULT_DOSStub_8ab3 {
  strings:
    $key_8ab3 = { de db [2] aa c3 [2] ed c1 [2] aa d0 [2] e4 dc [2] e8 d6 [2] ff dd [2] e4 93 [2] d9 }

  condition:
    any of them
}