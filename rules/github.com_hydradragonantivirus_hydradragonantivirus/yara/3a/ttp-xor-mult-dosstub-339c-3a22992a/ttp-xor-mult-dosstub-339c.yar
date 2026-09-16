rule TTP_XOR_MULT_DOSStub_339c {
  strings:
    $key_339c = { 67 f4 [2] 13 ec [2] 54 ee [2] 13 ff [2] 5d f3 [2] 51 f9 [2] 46 f2 [2] 5d bc [2] 60 }

  condition:
    any of them
}