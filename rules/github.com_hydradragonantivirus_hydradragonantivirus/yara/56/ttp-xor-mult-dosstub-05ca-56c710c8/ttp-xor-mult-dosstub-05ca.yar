rule TTP_XOR_MULT_DOSStub_05ca {
  strings:
    $key_05ca = { 51 a2 [2] 25 ba [2] 62 b8 [2] 25 a9 [2] 6b a5 [2] 67 af [2] 70 a4 [2] 6b ea [2] 56 }

  condition:
    any of them
}