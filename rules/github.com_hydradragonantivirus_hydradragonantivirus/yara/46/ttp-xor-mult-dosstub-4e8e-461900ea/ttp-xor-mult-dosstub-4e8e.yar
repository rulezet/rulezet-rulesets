rule TTP_XOR_MULT_DOSStub_4e8e {
  strings:
    $key_4e8e = { 1a e6 [2] 6e fe [2] 29 fc [2] 6e ed [2] 20 e1 [2] 2c eb [2] 3b e0 [2] 20 ae [2] 1d }

  condition:
    any of them
}