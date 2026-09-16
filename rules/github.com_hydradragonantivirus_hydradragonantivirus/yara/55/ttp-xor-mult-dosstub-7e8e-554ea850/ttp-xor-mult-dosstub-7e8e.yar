rule TTP_XOR_MULT_DOSStub_7e8e {
  strings:
    $key_7e8e = { 2a e6 [2] 5e fe [2] 19 fc [2] 5e ed [2] 10 e1 [2] 1c eb [2] 0b e0 [2] 10 ae [2] 2d }

  condition:
    any of them
}