rule TTP_XOR_MULT_DOSStub_ba54 {
  strings:
    $key_ba54 = { ee 3c [2] 9a 24 [2] dd 26 [2] 9a 37 [2] d4 3b [2] d8 31 [2] cf 3a [2] d4 74 [2] e9 }

  condition:
    any of them
}