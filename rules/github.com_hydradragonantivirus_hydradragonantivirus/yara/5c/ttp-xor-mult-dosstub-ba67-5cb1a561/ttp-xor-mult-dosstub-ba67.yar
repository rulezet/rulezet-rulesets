rule TTP_XOR_MULT_DOSStub_ba67 {
  strings:
    $key_ba67 = { ee 0f [2] 9a 17 [2] dd 15 [2] 9a 04 [2] d4 08 [2] d8 02 [2] cf 09 [2] d4 47 [2] e9 }

  condition:
    any of them
}