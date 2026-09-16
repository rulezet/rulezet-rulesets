rule TTP_XOR_MULT_DOSStub_069c {
  strings:
    $key_069c = { 52 f4 [2] 26 ec [2] 61 ee [2] 26 ff [2] 68 f3 [2] 64 f9 [2] 73 f2 [2] 68 bc [2] 55 }

  condition:
    any of them
}