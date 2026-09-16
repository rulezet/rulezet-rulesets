rule TTP_XOR_MULT_DOSStub_34ca {
  strings:
    $key_34ca = { 60 a2 [2] 14 ba [2] 53 b8 [2] 14 a9 [2] 5a a5 [2] 56 af [2] 41 a4 [2] 5a ea [2] 67 }

  condition:
    any of them
}