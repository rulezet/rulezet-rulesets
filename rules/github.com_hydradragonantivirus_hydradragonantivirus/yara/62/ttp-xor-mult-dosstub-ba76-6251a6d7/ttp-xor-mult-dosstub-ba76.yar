rule TTP_XOR_MULT_DOSStub_ba76 {
  strings:
    $key_ba76 = { ee 1e [2] 9a 06 [2] dd 04 [2] 9a 15 [2] d4 19 [2] d8 13 [2] cf 18 [2] d4 56 [2] e9 }

  condition:
    any of them
}