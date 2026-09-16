rule TTP_XOR_MULT_DOSStub_ba2b {
  strings:
    $key_ba2b = { ee 43 [2] 9a 5b [2] dd 59 [2] 9a 48 [2] d4 44 [2] d8 4e [2] cf 45 [2] d4 0b [2] e9 }

  condition:
    any of them
}