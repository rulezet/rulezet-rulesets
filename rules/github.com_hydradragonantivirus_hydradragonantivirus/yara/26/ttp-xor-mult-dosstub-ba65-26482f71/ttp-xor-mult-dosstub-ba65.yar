rule TTP_XOR_MULT_DOSStub_ba65 {
  strings:
    $key_ba65 = { ee 0d [2] 9a 15 [2] dd 17 [2] 9a 06 [2] d4 0a [2] d8 00 [2] cf 0b [2] d4 45 [2] e9 }

  condition:
    any of them
}