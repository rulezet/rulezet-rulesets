rule TTP_XOR_MULT_DOSStub_dfc5 {
  strings:
    $key_dfc5 = { 8b ad [2] ff b5 [2] b8 b7 [2] ff a6 [2] b1 aa [2] bd a0 [2] aa ab [2] b1 e5 [2] 8c }

  condition:
    any of them
}