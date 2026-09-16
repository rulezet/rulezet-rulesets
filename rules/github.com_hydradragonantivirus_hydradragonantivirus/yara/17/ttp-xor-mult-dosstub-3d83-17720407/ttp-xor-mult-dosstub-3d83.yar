rule TTP_XOR_MULT_DOSStub_3d83 {
  strings:
    $key_3d83 = { 69 eb [2] 1d f3 [2] 5a f1 [2] 1d e0 [2] 53 ec [2] 5f e6 [2] 48 ed [2] 53 a3 [2] 6e }

  condition:
    any of them
}