rule TTP_XOR_MULT_DOSStub_ba4a {
  strings:
    $key_ba4a = { ee 22 [2] 9a 3a [2] dd 38 [2] 9a 29 [2] d4 25 [2] d8 2f [2] cf 24 [2] d4 6a [2] e9 }

  condition:
    any of them
}