rule TTP_XOR_MULT_DOSStub_ba21 {
  strings:
    $key_ba21 = { ee 49 [2] 9a 51 [2] dd 53 [2] 9a 42 [2] d4 4e [2] d8 44 [2] cf 4f [2] d4 01 [2] e9 }

  condition:
    any of them
}