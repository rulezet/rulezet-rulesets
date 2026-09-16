rule TTP_XOR_MULT_DOSStub_8ec8 {
  strings:
    $key_8ec8 = { da a0 [2] ae b8 [2] e9 ba [2] ae ab [2] e0 a7 [2] ec ad [2] fb a6 [2] e0 e8 [2] dd }

  condition:
    any of them
}