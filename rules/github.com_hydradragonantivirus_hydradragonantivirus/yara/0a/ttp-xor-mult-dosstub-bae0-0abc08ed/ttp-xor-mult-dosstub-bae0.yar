rule TTP_XOR_MULT_DOSStub_bae0 {
  strings:
    $key_bae0 = { ee 88 [2] 9a 90 [2] dd 92 [2] 9a 83 [2] d4 8f [2] d8 85 [2] cf 8e [2] d4 c0 [2] e9 }

  condition:
    any of them
}