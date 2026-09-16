rule TTP_XOR_MULT_DOSStub_ba43 {
  strings:
    $key_ba43 = { ee 2b [2] 9a 33 [2] dd 31 [2] 9a 20 [2] d4 2c [2] d8 26 [2] cf 2d [2] d4 63 [2] e9 }

  condition:
    any of them
}