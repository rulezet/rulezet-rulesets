rule TTP_XOR_MULT_DOSStub_8ec9 {
  strings:
    $key_8ec9 = { da a1 [2] ae b9 [2] e9 bb [2] ae aa [2] e0 a6 [2] ec ac [2] fb a7 [2] e0 e9 [2] dd }

  condition:
    any of them
}