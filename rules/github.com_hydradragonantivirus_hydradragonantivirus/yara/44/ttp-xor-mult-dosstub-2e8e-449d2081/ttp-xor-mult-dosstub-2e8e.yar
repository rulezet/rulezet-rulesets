rule TTP_XOR_MULT_DOSStub_2e8e {
  strings:
    $key_2e8e = { 7a e6 [2] 0e fe [2] 49 fc [2] 0e ed [2] 40 e1 [2] 4c eb [2] 5b e0 [2] 40 ae [2] 7d }

  condition:
    any of them
}