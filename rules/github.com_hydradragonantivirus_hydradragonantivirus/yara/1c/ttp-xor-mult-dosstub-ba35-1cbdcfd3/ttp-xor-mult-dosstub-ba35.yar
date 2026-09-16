rule TTP_XOR_MULT_DOSStub_ba35 {
  strings:
    $key_ba35 = { ee 5d [2] 9a 45 [2] dd 47 [2] 9a 56 [2] d4 5a [2] d8 50 [2] cf 5b [2] d4 15 [2] e9 }

  condition:
    any of them
}