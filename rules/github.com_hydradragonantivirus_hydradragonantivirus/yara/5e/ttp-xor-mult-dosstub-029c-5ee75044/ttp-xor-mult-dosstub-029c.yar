rule TTP_XOR_MULT_DOSStub_029c {
  strings:
    $key_029c = { 56 f4 [2] 22 ec [2] 65 ee [2] 22 ff [2] 6c f3 [2] 60 f9 [2] 77 f2 [2] 6c bc [2] 51 }

  condition:
    any of them
}