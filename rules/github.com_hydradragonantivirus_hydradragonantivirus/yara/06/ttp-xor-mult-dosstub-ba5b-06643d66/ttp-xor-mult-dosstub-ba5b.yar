rule TTP_XOR_MULT_DOSStub_ba5b {
  strings:
    $key_ba5b = { ee 33 [2] 9a 2b [2] dd 29 [2] 9a 38 [2] d4 34 [2] d8 3e [2] cf 35 [2] d4 7b [2] e9 }

  condition:
    any of them
}