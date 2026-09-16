rule TTP_XOR_MULT_DOSStub_ba19 {
  strings:
    $key_ba19 = { ee 71 [2] 9a 69 [2] dd 6b [2] 9a 7a [2] d4 76 [2] d8 7c [2] cf 77 [2] d4 39 [2] e9 }

  condition:
    any of them
}