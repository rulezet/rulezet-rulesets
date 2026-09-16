rule TTP_XOR_MULT_DOSStub_bad4 {
  strings:
    $key_bad4 = { ee bc [2] 9a a4 [2] dd a6 [2] 9a b7 [2] d4 bb [2] d8 b1 [2] cf ba [2] d4 f4 [2] e9 }

  condition:
    any of them
}