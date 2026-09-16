rule TTP_XOR_MULT_DOSStub_15ca {
  strings:
    $key_15ca = { 41 a2 [2] 35 ba [2] 72 b8 [2] 35 a9 [2] 7b a5 [2] 77 af [2] 60 a4 [2] 7b ea [2] 46 }

  condition:
    any of them
}