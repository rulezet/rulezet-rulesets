rule TTP_XOR_MULT_DOSStub_ba85 {
  strings:
    $key_ba85 = { ee ed [2] 9a f5 [2] dd f7 [2] 9a e6 [2] d4 ea [2] d8 e0 [2] cf eb [2] d4 a5 [2] e9 }

  condition:
    any of them
}