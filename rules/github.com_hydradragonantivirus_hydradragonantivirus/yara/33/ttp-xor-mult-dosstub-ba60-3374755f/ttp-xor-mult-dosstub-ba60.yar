rule TTP_XOR_MULT_DOSStub_ba60 {
  strings:
    $key_ba60 = { ee 08 [2] 9a 10 [2] dd 12 [2] 9a 03 [2] d4 0f [2] d8 05 [2] cf 0e [2] d4 40 [2] e9 }

  condition:
    any of them
}