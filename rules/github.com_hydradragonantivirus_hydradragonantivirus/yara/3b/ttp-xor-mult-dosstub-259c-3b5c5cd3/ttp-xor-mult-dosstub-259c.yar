rule TTP_XOR_MULT_DOSStub_259c {
  strings:
    $key_259c = { 71 f4 [2] 05 ec [2] 42 ee [2] 05 ff [2] 4b f3 [2] 47 f9 [2] 50 f2 [2] 4b bc [2] 76 }

  condition:
    any of them
}