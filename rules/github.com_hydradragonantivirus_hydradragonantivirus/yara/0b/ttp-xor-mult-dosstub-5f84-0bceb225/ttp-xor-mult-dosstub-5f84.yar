rule TTP_XOR_MULT_DOSStub_5f84 {
  strings:
    $key_5f84 = { 0b ec [2] 7f f4 [2] 38 f6 [2] 7f e7 [2] 31 eb [2] 3d e1 [2] 2a ea [2] 31 a4 [2] 0c }

  condition:
    any of them
}