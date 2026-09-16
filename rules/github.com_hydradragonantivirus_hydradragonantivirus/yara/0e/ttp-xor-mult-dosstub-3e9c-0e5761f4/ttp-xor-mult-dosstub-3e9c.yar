rule TTP_XOR_MULT_DOSStub_3e9c {
  strings:
    $key_3e9c = { 6a f4 [2] 1e ec [2] 59 ee [2] 1e ff [2] 50 f3 [2] 5c f9 [2] 4b f2 [2] 50 bc [2] 6d }

  condition:
    any of them
}