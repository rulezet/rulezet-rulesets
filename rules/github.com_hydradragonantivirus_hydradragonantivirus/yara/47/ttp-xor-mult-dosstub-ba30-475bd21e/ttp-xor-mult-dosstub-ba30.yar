rule TTP_XOR_MULT_DOSStub_ba30 {
  strings:
    $key_ba30 = { ee 58 [2] 9a 40 [2] dd 42 [2] 9a 53 [2] d4 5f [2] d8 55 [2] cf 5e [2] d4 10 [2] e9 }

  condition:
    any of them
}