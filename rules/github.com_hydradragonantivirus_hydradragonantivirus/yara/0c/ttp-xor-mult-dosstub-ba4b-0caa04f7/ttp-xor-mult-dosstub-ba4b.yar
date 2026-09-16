rule TTP_XOR_MULT_DOSStub_ba4b {
  strings:
    $key_ba4b = { ee 23 [2] 9a 3b [2] dd 39 [2] 9a 28 [2] d4 24 [2] d8 2e [2] cf 25 [2] d4 6b [2] e9 }

  condition:
    any of them
}