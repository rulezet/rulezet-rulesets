rule TTP_XOR_MULT_DOSStub_baf8 {
  strings:
    $key_baf8 = { ee 90 [2] 9a 88 [2] dd 8a [2] 9a 9b [2] d4 97 [2] d8 9d [2] cf 96 [2] d4 d8 [2] e9 }

  condition:
    any of them
}