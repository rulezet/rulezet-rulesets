rule TTP_XOR_MULT_DOSStub_dcd8 {
  strings:
    $key_dcd8 = { 88 b0 [2] fc a8 [2] bb aa [2] fc bb [2] b2 b7 [2] be bd [2] a9 b6 [2] b2 f8 [2] 8f }

  condition:
    any of them
}