rule TTP_XOR_MULT_DOSStub_3a8e {
  strings:
    $key_3a8e = { 6e e6 [2] 1a fe [2] 5d fc [2] 1a ed [2] 54 e1 [2] 58 eb [2] 4f e0 [2] 54 ae [2] 69 }

  condition:
    any of them
}