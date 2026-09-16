rule TTP_XOR_MULT_DOSStub_ba13 {
  strings:
    $key_ba13 = { ee 7b [2] 9a 63 [2] dd 61 [2] 9a 70 [2] d4 7c [2] d8 76 [2] cf 7d [2] d4 33 [2] e9 }

  condition:
    any of them
}