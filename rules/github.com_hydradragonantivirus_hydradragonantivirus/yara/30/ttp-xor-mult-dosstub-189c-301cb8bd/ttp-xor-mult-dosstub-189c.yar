rule TTP_XOR_MULT_DOSStub_189c {
  strings:
    $key_189c = { 4c f4 [2] 38 ec [2] 7f ee [2] 38 ff [2] 76 f3 [2] 7a f9 [2] 6d f2 [2] 76 bc [2] 4b }

  condition:
    any of them
}