rule TTP_XOR_MULT_DOSStub_4d9c {
  strings:
    $key_4d9c = { 19 f4 [2] 6d ec [2] 2a ee [2] 6d ff [2] 23 f3 [2] 2f f9 [2] 38 f2 [2] 23 bc [2] 1e }

  condition:
    any of them
}