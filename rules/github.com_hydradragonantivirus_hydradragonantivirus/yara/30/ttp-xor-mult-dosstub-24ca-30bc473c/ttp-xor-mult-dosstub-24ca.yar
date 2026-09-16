rule TTP_XOR_MULT_DOSStub_24ca {
  strings:
    $key_24ca = { 70 a2 [2] 04 ba [2] 43 b8 [2] 04 a9 [2] 4a a5 [2] 46 af [2] 51 a4 [2] 4a ea [2] 77 }

  condition:
    any of them
}