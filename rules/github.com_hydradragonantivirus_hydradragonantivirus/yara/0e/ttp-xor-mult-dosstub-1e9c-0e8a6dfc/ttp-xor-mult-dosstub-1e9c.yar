rule TTP_XOR_MULT_DOSStub_1e9c {
  strings:
    $key_1e9c = { 4a f4 [2] 3e ec [2] 79 ee [2] 3e ff [2] 70 f3 [2] 7c f9 [2] 6b f2 [2] 70 bc [2] 4d }

  condition:
    any of them
}