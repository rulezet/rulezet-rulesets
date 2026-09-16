rule TTP_XOR_MULT_DOSStub_ba0a {
  strings:
    $key_ba0a = { ee 62 [2] 9a 7a [2] dd 78 [2] 9a 69 [2] d4 65 [2] d8 6f [2] cf 64 [2] d4 2a [2] e9 }

  condition:
    any of them
}