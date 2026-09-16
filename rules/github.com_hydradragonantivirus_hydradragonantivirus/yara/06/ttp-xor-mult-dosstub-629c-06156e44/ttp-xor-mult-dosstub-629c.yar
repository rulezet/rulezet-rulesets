rule TTP_XOR_MULT_DOSStub_629c {
  strings:
    $key_629c = { 36 f4 [2] 42 ec [2] 05 ee [2] 42 ff [2] 0c f3 [2] 00 f9 [2] 17 f2 [2] 0c bc [2] 31 }

  condition:
    any of them
}