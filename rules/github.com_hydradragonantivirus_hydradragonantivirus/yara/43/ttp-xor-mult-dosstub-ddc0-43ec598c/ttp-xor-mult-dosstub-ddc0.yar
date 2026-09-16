rule TTP_XOR_MULT_DOSStub_ddc0 {
  strings:
    $key_ddc0 = { 89 a8 [2] fd b0 [2] ba b2 [2] fd a3 [2] b3 af [2] bf a5 [2] a8 ae [2] b3 e0 [2] 8e }

  condition:
    any of them
}