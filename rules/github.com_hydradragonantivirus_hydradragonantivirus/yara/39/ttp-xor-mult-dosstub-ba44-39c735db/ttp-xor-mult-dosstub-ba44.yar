rule TTP_XOR_MULT_DOSStub_ba44 {
  strings:
    $key_ba44 = { ee 2c [2] 9a 34 [2] dd 36 [2] 9a 27 [2] d4 2b [2] d8 21 [2] cf 2a [2] d4 64 [2] e9 }

  condition:
    any of them
}