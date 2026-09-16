rule TTP_XOR_MULT_DOSStub_ba41 {
  strings:
    $key_ba41 = { ee 29 [2] 9a 31 [2] dd 33 [2] 9a 22 [2] d4 2e [2] d8 24 [2] cf 2f [2] d4 61 [2] e9 }

  condition:
    any of them
}