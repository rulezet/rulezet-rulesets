rule TTP_XOR_MULT_DOSStub_518d {
  strings:
    $key_518d = { 05 e5 [2] 71 fd [2] 36 ff [2] 71 ee [2] 3f e2 [2] 33 e8 [2] 24 e3 [2] 3f ad [2] 02 }

  condition:
    any of them
}