rule TTP_XOR_MULT_DOSStub_38ca {
  strings:
    $key_38ca = { 6c a2 [2] 18 ba [2] 5f b8 [2] 18 a9 [2] 56 a5 [2] 5a af [2] 4d a4 [2] 56 ea [2] 6b }

  condition:
    any of them
}