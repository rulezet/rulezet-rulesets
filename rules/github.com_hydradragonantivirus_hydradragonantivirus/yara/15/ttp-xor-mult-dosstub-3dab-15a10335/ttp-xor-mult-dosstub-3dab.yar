rule TTP_XOR_MULT_DOSStub_3dab {
  strings:
    $key_3dab = { 69 c3 [2] 1d db [2] 5a d9 [2] 1d c8 [2] 53 c4 [2] 5f ce [2] 48 c5 [2] 53 8b [2] 6e }

  condition:
    any of them
}