rule TTP_XOR_MULT_DOSStub_499c {
  strings:
    $key_499c = { 1d f4 [2] 69 ec [2] 2e ee [2] 69 ff [2] 27 f3 [2] 2b f9 [2] 3c f2 [2] 27 bc [2] 1a }

  condition:
    any of them
}