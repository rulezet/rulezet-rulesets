rule TTP_XOR_MULT_DOSStub_6a9c {
  strings:
    $key_6a9c = { 3e f4 [2] 4a ec [2] 0d ee [2] 4a ff [2] 04 f3 [2] 08 f9 [2] 1f f2 [2] 04 bc [2] 39 }

  condition:
    any of them
}