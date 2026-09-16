rule TTP_XOR_MULT_DOSStub_6b83 {
  strings:
    $key_6b83 = { 3f eb [2] 4b f3 [2] 0c f1 [2] 4b e0 [2] 05 ec [2] 09 e6 [2] 1e ed [2] 05 a3 [2] 38 }

  condition:
    any of them
}