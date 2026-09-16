rule TTP_XOR_MULT_DOSStub_7f8e {
  strings:
    $key_7f8e = { 2b e6 [2] 5f fe [2] 18 fc [2] 5f ed [2] 11 e1 [2] 1d eb [2] 0a e0 [2] 11 ae [2] 2c }

  condition:
    any of them
}