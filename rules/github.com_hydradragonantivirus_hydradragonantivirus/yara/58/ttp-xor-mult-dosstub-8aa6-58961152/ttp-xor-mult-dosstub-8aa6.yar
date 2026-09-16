rule TTP_XOR_MULT_DOSStub_8aa6 {
  strings:
    $key_8aa6 = { de ce [2] aa d6 [2] ed d4 [2] aa c5 [2] e4 c9 [2] e8 c3 [2] ff c8 [2] e4 86 [2] d9 }

  condition:
    any of them
}