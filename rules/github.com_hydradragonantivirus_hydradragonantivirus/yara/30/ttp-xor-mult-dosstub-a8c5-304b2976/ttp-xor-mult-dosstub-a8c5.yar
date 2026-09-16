rule TTP_XOR_MULT_DOSStub_a8c5 {
  strings:
    $key_a8c5 = { fc ad [2] 88 b5 [2] cf b7 [2] 88 a6 [2] c6 aa [2] ca a0 [2] dd ab [2] c6 e5 [2] fb }

  condition:
    any of them
}