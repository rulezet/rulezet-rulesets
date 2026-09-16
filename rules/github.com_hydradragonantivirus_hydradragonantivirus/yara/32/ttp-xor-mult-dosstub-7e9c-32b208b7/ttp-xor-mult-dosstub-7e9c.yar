rule TTP_XOR_MULT_DOSStub_7e9c {
  strings:
    $key_7e9c = { 2a f4 [2] 5e ec [2] 19 ee [2] 5e ff [2] 10 f3 [2] 1c f9 [2] 0b f2 [2] 10 bc [2] 2d }

  condition:
    any of them
}