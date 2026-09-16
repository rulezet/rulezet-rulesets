rule TTP_XOR_MULT_DOSStub_baf5 {
  strings:
    $key_baf5 = { ee 9d [2] 9a 85 [2] dd 87 [2] 9a 96 [2] d4 9a [2] d8 90 [2] cf 9b [2] d4 d5 [2] e9 }

  condition:
    any of them
}