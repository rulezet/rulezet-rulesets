rule TTP_XOR_MULT_DOSStub_ba98 {
  strings:
    $key_ba98 = { ee f0 [2] 9a e8 [2] dd ea [2] 9a fb [2] d4 f7 [2] d8 fd [2] cf f6 [2] d4 b8 [2] e9 }

  condition:
    any of them
}