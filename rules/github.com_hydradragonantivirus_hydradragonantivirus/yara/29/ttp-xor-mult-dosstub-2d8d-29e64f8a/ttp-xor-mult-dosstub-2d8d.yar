rule TTP_XOR_MULT_DOSStub_2d8d {
  strings:
    $key_2d8d = { 79 e5 [2] 0d fd [2] 4a ff [2] 0d ee [2] 43 e2 [2] 4f e8 [2] 58 e3 [2] 43 ad [2] 7e }

  condition:
    any of them
}