rule TTP_XOR_MULT_DOSStub_4d83 {
  strings:
    $key_4d83 = { 19 eb [2] 6d f3 [2] 2a f1 [2] 6d e0 [2] 23 ec [2] 2f e6 [2] 38 ed [2] 23 a3 [2] 1e }

  condition:
    any of them
}