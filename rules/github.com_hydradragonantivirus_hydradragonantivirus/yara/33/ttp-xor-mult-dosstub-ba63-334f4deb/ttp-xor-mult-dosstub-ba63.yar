rule TTP_XOR_MULT_DOSStub_ba63 {
  strings:
    $key_ba63 = { ee 0b [2] 9a 13 [2] dd 11 [2] 9a 00 [2] d4 0c [2] d8 06 [2] cf 0d [2] d4 43 [2] e9 }

  condition:
    any of them
}