rule TTP_XOR_MULT_DOSStub_4f8e {
  strings:
    $key_4f8e = { 1b e6 [2] 6f fe [2] 28 fc [2] 6f ed [2] 21 e1 [2] 2d eb [2] 3a e0 [2] 21 ae [2] 1c }

  condition:
    any of them
}