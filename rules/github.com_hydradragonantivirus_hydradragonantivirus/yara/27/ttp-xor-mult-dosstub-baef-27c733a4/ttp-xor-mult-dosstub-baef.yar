rule TTP_XOR_MULT_DOSStub_baef {
  strings:
    $key_baef = { ee 87 [2] 9a 9f [2] dd 9d [2] 9a 8c [2] d4 80 [2] d8 8a [2] cf 81 [2] d4 cf [2] e9 }

  condition:
    any of them
}