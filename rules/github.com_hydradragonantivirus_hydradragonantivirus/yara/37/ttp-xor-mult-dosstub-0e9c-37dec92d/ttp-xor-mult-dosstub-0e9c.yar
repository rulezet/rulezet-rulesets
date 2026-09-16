rule TTP_XOR_MULT_DOSStub_0e9c {
  strings:
    $key_0e9c = { 5a f4 [2] 2e ec [2] 69 ee [2] 2e ff [2] 60 f3 [2] 6c f9 [2] 7b f2 [2] 60 bc [2] 5d }

  condition:
    any of them
}