rule TTP_XOR_MULT_DOSStub_ba9c {
  strings:
    $key_ba9c = { ee f4 [2] 9a ec [2] dd ee [2] 9a ff [2] d4 f3 [2] d8 f9 [2] cf f2 [2] d4 bc [2] e9 }

  condition:
    any of them
}