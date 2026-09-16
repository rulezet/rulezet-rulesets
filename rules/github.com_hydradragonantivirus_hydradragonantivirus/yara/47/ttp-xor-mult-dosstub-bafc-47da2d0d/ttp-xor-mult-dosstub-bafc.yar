rule TTP_XOR_MULT_DOSStub_bafc {
  strings:
    $key_bafc = { ee 94 [2] 9a 8c [2] dd 8e [2] 9a 9f [2] d4 93 [2] d8 99 [2] cf 92 [2] d4 dc [2] e9 }

  condition:
    any of them
}