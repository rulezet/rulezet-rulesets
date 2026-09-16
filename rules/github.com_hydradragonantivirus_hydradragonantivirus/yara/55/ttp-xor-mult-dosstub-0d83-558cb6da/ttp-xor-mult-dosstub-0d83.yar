rule TTP_XOR_MULT_DOSStub_0d83 {
  strings:
    $key_0d83 = { 59 eb [2] 2d f3 [2] 6a f1 [2] 2d e0 [2] 63 ec [2] 6f e6 [2] 78 ed [2] 63 a3 [2] 5e }

  condition:
    any of them
}