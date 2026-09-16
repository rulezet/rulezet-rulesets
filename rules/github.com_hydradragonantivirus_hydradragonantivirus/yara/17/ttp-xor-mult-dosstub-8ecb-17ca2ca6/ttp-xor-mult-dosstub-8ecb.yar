rule TTP_XOR_MULT_DOSStub_8ecb {
  strings:
    $key_8ecb = { da a3 [2] ae bb [2] e9 b9 [2] ae a8 [2] e0 a4 [2] ec ae [2] fb a5 [2] e0 eb [2] dd }

  condition:
    any of them
}