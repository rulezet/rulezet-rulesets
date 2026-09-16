rule TTP_XOR_MULT_DOSStub_299c {
  strings:
    $key_299c = { 7d f4 [2] 09 ec [2] 4e ee [2] 09 ff [2] 47 f3 [2] 4b f9 [2] 5c f2 [2] 47 bc [2] 7a }

  condition:
    any of them
}