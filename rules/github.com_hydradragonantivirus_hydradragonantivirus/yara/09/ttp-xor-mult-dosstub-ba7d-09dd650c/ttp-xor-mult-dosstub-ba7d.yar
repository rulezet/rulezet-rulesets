rule TTP_XOR_MULT_DOSStub_ba7d {
  strings:
    $key_ba7d = { ee 15 [2] 9a 0d [2] dd 0f [2] 9a 1e [2] d4 12 [2] d8 18 [2] cf 13 [2] d4 5d [2] e9 }

  condition:
    any of them
}