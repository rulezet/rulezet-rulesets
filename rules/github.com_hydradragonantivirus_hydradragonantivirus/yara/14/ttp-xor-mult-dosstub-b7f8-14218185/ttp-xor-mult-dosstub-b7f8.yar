rule TTP_XOR_MULT_DOSStub_b7f8 {
  strings:
    $key_b7f8 = { e3 90 [2] 97 88 [2] d0 8a [2] 97 9b [2] d9 97 [2] d5 9d [2] c2 96 [2] d9 d8 [2] e4 }

  condition:
    any of them
}