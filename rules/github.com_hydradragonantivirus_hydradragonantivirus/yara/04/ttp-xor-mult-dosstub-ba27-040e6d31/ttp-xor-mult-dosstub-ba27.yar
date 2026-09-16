rule TTP_XOR_MULT_DOSStub_ba27 {
  strings:
    $key_ba27 = { ee 4f [2] 9a 57 [2] dd 55 [2] 9a 44 [2] d4 48 [2] d8 42 [2] cf 49 [2] d4 07 [2] e9 }

  condition:
    any of them
}