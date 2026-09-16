rule TTP_XOR_MULT_DOSStub_ba42 {
  strings:
    $key_ba42 = { ee 2a [2] 9a 32 [2] dd 30 [2] 9a 21 [2] d4 2d [2] d8 27 [2] cf 2c [2] d4 62 [2] e9 }

  condition:
    any of them
}