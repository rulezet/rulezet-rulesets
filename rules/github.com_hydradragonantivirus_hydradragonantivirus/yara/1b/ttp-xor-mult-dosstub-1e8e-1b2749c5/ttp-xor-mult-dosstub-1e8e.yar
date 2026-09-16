rule TTP_XOR_MULT_DOSStub_1e8e {
  strings:
    $key_1e8e = { 4a e6 [2] 3e fe [2] 79 fc [2] 3e ed [2] 70 e1 [2] 7c eb [2] 6b e0 [2] 70 ae [2] 4d }

  condition:
    any of them
}