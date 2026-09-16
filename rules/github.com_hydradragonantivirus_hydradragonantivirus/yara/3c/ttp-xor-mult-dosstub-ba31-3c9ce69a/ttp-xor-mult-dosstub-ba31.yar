rule TTP_XOR_MULT_DOSStub_ba31 {
  strings:
    $key_ba31 = { ee 59 [2] 9a 41 [2] dd 43 [2] 9a 52 [2] d4 5e [2] d8 54 [2] cf 5f [2] d4 11 [2] e9 }

  condition:
    any of them
}