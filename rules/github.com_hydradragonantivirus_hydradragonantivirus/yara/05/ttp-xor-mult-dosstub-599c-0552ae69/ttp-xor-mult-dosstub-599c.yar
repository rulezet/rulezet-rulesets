rule TTP_XOR_MULT_DOSStub_599c {
  strings:
    $key_599c = { 0d f4 [2] 79 ec [2] 3e ee [2] 79 ff [2] 37 f3 [2] 3b f9 [2] 2c f2 [2] 37 bc [2] 0a }

  condition:
    any of them
}