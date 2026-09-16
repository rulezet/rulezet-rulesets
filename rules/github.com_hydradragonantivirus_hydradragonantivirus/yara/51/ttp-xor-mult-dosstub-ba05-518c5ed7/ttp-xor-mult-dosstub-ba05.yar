rule TTP_XOR_MULT_DOSStub_ba05 {
  strings:
    $key_ba05 = { ee 6d [2] 9a 75 [2] dd 77 [2] 9a 66 [2] d4 6a [2] d8 60 [2] cf 6b [2] d4 25 [2] e9 }

  condition:
    any of them
}