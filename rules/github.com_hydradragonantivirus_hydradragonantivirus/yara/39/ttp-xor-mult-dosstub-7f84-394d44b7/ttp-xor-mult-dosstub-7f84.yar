rule TTP_XOR_MULT_DOSStub_7f84 {
  strings:
    $key_7f84 = { 2b ec [2] 5f f4 [2] 18 f6 [2] 5f e7 [2] 11 eb [2] 1d e1 [2] 0a ea [2] 11 a4 [2] 2c }

  condition:
    any of them
}