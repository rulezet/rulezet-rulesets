rule TTP_XOR_MULT_DOSStub_ba56 {
  strings:
    $key_ba56 = { ee 3e [2] 9a 26 [2] dd 24 [2] 9a 35 [2] d4 39 [2] d8 33 [2] cf 38 [2] d4 76 [2] e9 }

  condition:
    any of them
}