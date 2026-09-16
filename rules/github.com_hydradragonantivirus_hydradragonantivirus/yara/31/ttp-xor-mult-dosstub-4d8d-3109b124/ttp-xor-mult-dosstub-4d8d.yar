rule TTP_XOR_MULT_DOSStub_4d8d {
  strings:
    $key_4d8d = { 19 e5 [2] 6d fd [2] 2a ff [2] 6d ee [2] 23 e2 [2] 2f e8 [2] 38 e3 [2] 23 ad [2] 1e }

  condition:
    any of them
}