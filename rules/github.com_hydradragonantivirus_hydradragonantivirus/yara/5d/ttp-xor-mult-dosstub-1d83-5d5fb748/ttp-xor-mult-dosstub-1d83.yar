rule TTP_XOR_MULT_DOSStub_1d83 {
  strings:
    $key_1d83 = { 49 eb [2] 3d f3 [2] 7a f1 [2] 3d e0 [2] 73 ec [2] 7f e6 [2] 68 ed [2] 73 a3 [2] 4e }

  condition:
    any of them
}