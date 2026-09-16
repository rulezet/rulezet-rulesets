rule TTP_XOR_MULT_DOSStub_6d83 {
  strings:
    $key_6d83 = { 39 eb [2] 4d f3 [2] 0a f1 [2] 4d e0 [2] 03 ec [2] 0f e6 [2] 18 ed [2] 03 a3 [2] 3e }

  condition:
    any of them
}