rule TTP_XOR_MULT_DOSStub_559c {
  strings:
    $key_559c = { 01 f4 [2] 75 ec [2] 32 ee [2] 75 ff [2] 3b f3 [2] 37 f9 [2] 20 f2 [2] 3b bc [2] 06 }

  condition:
    any of them
}