rule TTP_XOR_MULT_DOSStub_1a8e {
  strings:
    $key_1a8e = { 4e e6 [2] 3a fe [2] 7d fc [2] 3a ed [2] 74 e1 [2] 78 eb [2] 6f e0 [2] 74 ae [2] 49 }

  condition:
    any of them
}