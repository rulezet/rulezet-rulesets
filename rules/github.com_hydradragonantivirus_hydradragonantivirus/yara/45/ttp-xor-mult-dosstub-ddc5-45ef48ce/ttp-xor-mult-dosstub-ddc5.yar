rule TTP_XOR_MULT_DOSStub_ddc5 {
  strings:
    $key_ddc5 = { 89 ad [2] fd b5 [2] ba b7 [2] fd a6 [2] b3 aa [2] bf a0 [2] a8 ab [2] b3 e5 [2] 8e }

  condition:
    any of them
}