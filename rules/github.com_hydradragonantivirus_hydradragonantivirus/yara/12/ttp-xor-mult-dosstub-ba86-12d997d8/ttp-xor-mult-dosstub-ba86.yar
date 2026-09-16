rule TTP_XOR_MULT_DOSStub_ba86 {
  strings:
    $key_ba86 = { ee ee [2] 9a f6 [2] dd f4 [2] 9a e5 [2] d4 e9 [2] d8 e3 [2] cf e8 [2] d4 a6 [2] e9 }

  condition:
    any of them
}