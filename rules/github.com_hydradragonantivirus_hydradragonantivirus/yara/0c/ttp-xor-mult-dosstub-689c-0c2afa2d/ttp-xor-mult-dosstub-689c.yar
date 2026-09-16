rule TTP_XOR_MULT_DOSStub_689c {
  strings:
    $key_689c = { 3c f4 [2] 48 ec [2] 0f ee [2] 48 ff [2] 06 f3 [2] 0a f9 [2] 1d f2 [2] 06 bc [2] 3b }

  condition:
    any of them
}