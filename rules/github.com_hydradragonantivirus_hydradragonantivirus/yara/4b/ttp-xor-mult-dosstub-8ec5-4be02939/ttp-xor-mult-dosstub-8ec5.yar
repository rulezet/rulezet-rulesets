rule TTP_XOR_MULT_DOSStub_8ec5 {
  strings:
    $key_8ec5 = { da ad [2] ae b5 [2] e9 b7 [2] ae a6 [2] e0 aa [2] ec a0 [2] fb ab [2] e0 e5 [2] dd }

  condition:
    any of them
}