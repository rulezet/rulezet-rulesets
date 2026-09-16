rule TTP_XOR_MULT_DOSStub_ba4c {
  strings:
    $key_ba4c = { ee 24 [2] 9a 3c [2] dd 3e [2] 9a 2f [2] d4 23 [2] d8 29 [2] cf 22 [2] d4 6c [2] e9 }

  condition:
    any of them
}