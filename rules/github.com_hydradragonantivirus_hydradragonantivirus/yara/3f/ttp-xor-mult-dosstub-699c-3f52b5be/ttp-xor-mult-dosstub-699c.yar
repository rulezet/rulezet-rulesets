rule TTP_XOR_MULT_DOSStub_699c {
  strings:
    $key_699c = { 3d f4 [2] 49 ec [2] 0e ee [2] 49 ff [2] 07 f3 [2] 0b f9 [2] 1c f2 [2] 07 bc [2] 3a }

  condition:
    any of them
}