rule TTP_XOR_MULT_DOSStub_3e8e {
  strings:
    $key_3e8e = { 6a e6 [2] 1e fe [2] 59 fc [2] 1e ed [2] 50 e1 [2] 5c eb [2] 4b e0 [2] 50 ae [2] 6d }

  condition:
    any of them
}