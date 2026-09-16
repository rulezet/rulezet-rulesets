rule TTP_XOR_MULT_DOSStub_459c {
  strings:
    $key_459c = { 11 f4 [2] 65 ec [2] 22 ee [2] 65 ff [2] 2b f3 [2] 27 f9 [2] 30 f2 [2] 2b bc [2] 16 }

  condition:
    any of them
}