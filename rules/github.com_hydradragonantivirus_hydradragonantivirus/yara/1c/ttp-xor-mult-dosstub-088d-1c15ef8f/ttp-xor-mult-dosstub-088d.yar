rule TTP_XOR_MULT_DOSStub_088d {
  strings:
    $key_088d = { 5c e5 [2] 28 fd [2] 6f ff [2] 28 ee [2] 66 e2 [2] 6a e8 [2] 7d e3 [2] 66 ad [2] 5b }

  condition:
    any of them
}