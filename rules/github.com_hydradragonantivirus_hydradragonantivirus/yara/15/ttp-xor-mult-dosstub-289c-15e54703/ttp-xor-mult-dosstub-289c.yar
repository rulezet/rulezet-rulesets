rule TTP_XOR_MULT_DOSStub_289c {
  strings:
    $key_289c = { 7c f4 [2] 08 ec [2] 4f ee [2] 08 ff [2] 46 f3 [2] 4a f9 [2] 5d f2 [2] 46 bc [2] 7b }

  condition:
    any of them
}