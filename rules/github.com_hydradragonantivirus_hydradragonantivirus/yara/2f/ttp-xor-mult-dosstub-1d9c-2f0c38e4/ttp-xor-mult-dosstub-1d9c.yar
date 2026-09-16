rule TTP_XOR_MULT_DOSStub_1d9c {
  strings:
    $key_1d9c = { 49 f4 [2] 3d ec [2] 7a ee [2] 3d ff [2] 73 f3 [2] 7f f9 [2] 68 f2 [2] 73 bc [2] 4e }

  condition:
    any of them
}