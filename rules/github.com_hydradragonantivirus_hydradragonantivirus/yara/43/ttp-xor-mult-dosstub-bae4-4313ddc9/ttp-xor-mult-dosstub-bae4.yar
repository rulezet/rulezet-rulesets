rule TTP_XOR_MULT_DOSStub_bae4 {
  strings:
    $key_bae4 = { ee 8c [2] 9a 94 [2] dd 96 [2] 9a 87 [2] d4 8b [2] d8 81 [2] cf 8a [2] d4 c4 [2] e9 }

  condition:
    any of them
}