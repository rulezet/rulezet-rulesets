rule TTP_XOR_MULT_DOSStub_ba7b {
  strings:
    $key_ba7b = { ee 13 [2] 9a 0b [2] dd 09 [2] 9a 18 [2] d4 14 [2] d8 1e [2] cf 15 [2] d4 5b [2] e9 }

  condition:
    any of them
}