rule TTP_XOR_MULT_DOSStub_ba61 {
  strings:
    $key_ba61 = { ee 09 [2] 9a 11 [2] dd 13 [2] 9a 02 [2] d4 0e [2] d8 04 [2] cf 0f [2] d4 41 [2] e9 }

  condition:
    any of them
}