rule TTP_XOR_MULT_DOSStub_059c {
  strings:
    $key_059c = { 51 f4 [2] 25 ec [2] 62 ee [2] 25 ff [2] 6b f3 [2] 67 f9 [2] 70 f2 [2] 6b bc [2] 56 }

  condition:
    any of them
}