rule TTP_XOR_MULT_DOSStub_ba20 {
  strings:
    $key_ba20 = { ee 48 [2] 9a 50 [2] dd 52 [2] 9a 43 [2] d4 4f [2] d8 45 [2] cf 4e [2] d4 00 [2] e9 }

  condition:
    any of them
}