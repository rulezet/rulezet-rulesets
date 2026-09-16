rule TTP_XOR_MULT_DOSStub_dda9 {
  strings:
    $key_dda9 = { 89 c1 [2] fd d9 [2] ba db [2] fd ca [2] b3 c6 [2] bf cc [2] a8 c7 [2] b3 89 [2] 8e }

  condition:
    any of them
}