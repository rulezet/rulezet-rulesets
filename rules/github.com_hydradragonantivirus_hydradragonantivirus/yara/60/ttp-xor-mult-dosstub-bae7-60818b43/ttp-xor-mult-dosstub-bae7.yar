rule TTP_XOR_MULT_DOSStub_bae7 {
  strings:
    $key_bae7 = { ee 8f [2] 9a 97 [2] dd 95 [2] 9a 84 [2] d4 88 [2] d8 82 [2] cf 89 [2] d4 c7 [2] e9 }

  condition:
    any of them
}