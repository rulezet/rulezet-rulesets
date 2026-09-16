rule TTP_XOR_MULT_DOSStub_2d9c {
  strings:
    $key_2d9c = { 79 f4 [2] 0d ec [2] 4a ee [2] 0d ff [2] 43 f3 [2] 4f f9 [2] 58 f2 [2] 43 bc [2] 7e }

  condition:
    any of them
}