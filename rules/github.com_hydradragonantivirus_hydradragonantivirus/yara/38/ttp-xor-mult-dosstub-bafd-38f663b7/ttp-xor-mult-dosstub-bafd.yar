rule TTP_XOR_MULT_DOSStub_bafd {
  strings:
    $key_bafd = { ee 95 [2] 9a 8d [2] dd 8f [2] 9a 9e [2] d4 92 [2] d8 98 [2] cf 93 [2] d4 dd [2] e9 }

  condition:
    any of them
}