rule TTP_XOR_MULT_DOSStub_ba96 {
  strings:
    $key_ba96 = { ee fe [2] 9a e6 [2] dd e4 [2] 9a f5 [2] d4 f9 [2] d8 f3 [2] cf f8 [2] d4 b6 [2] e9 }

  condition:
    any of them
}