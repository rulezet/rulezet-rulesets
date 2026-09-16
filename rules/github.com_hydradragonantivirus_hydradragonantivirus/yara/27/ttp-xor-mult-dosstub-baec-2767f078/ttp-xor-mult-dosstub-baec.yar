rule TTP_XOR_MULT_DOSStub_baec {
  strings:
    $key_baec = { ee 84 [2] 9a 9c [2] dd 9e [2] 9a 8f [2] d4 83 [2] d8 89 [2] cf 82 [2] d4 cc [2] e9 }

  condition:
    any of them
}