rule TTP_XOR_MULT_DOSStub_5d83 {
  strings:
    $key_5d83 = { 09 eb [2] 7d f3 [2] 3a f1 [2] 7d e0 [2] 33 ec [2] 3f e6 [2] 28 ed [2] 33 a3 [2] 0e }

  condition:
    any of them
}