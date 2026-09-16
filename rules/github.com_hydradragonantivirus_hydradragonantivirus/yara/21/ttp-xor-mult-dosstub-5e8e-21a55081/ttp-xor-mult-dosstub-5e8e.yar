rule TTP_XOR_MULT_DOSStub_5e8e {
  strings:
    $key_5e8e = { 0a e6 [2] 7e fe [2] 39 fc [2] 7e ed [2] 30 e1 [2] 3c eb [2] 2b e0 [2] 30 ae [2] 0d }

  condition:
    any of them
}