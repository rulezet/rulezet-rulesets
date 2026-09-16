rule TTP_XOR_MULT_DOSStub_ba26 {
  strings:
    $key_ba26 = { ee 4e [2] 9a 56 [2] dd 54 [2] 9a 45 [2] d4 49 [2] d8 43 [2] cf 48 [2] d4 06 [2] e9 }

  condition:
    any of them
}