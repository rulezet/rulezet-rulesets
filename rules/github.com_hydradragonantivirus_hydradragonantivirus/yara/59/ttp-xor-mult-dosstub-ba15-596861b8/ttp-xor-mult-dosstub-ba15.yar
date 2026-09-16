rule TTP_XOR_MULT_DOSStub_ba15 {
  strings:
    $key_ba15 = { ee 7d [2] 9a 65 [2] dd 67 [2] 9a 76 [2] d4 7a [2] d8 70 [2] cf 7b [2] d4 35 [2] e9 }

  condition:
    any of them
}