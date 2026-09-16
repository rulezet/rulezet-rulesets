rule TTP_XOR_MULT_DOSStub_baeb {
  strings:
    $key_baeb = { ee 83 [2] 9a 9b [2] dd 99 [2] 9a 88 [2] d4 84 [2] d8 8e [2] cf 85 [2] d4 cb [2] e9 }

  condition:
    any of them
}