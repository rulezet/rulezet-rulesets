rule TTP_XOR_MULT_DOSStub_ba37 {
  strings:
    $key_ba37 = { ee 5f [2] 9a 47 [2] dd 45 [2] 9a 54 [2] d4 58 [2] d8 52 [2] cf 59 [2] d4 17 [2] e9 }

  condition:
    any of them
}