rule TTP_XOR_MULT_DOSStub_dccb {
  strings:
    $key_dccb = { 88 a3 [2] fc bb [2] bb b9 [2] fc a8 [2] b2 a4 [2] be ae [2] a9 a5 [2] b2 eb [2] 8f }

  condition:
    any of them
}