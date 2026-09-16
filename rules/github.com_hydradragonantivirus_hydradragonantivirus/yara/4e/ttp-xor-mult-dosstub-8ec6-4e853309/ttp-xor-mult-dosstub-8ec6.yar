rule TTP_XOR_MULT_DOSStub_8ec6 {
  strings:
    $key_8ec6 = { da ae [2] ae b6 [2] e9 b4 [2] ae a5 [2] e0 a9 [2] ec a3 [2] fb a8 [2] e0 e6 [2] dd }

  condition:
    any of them
}