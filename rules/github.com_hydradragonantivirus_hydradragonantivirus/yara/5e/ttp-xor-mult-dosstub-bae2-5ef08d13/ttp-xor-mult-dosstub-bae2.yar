rule TTP_XOR_MULT_DOSStub_bae2 {
  strings:
    $key_bae2 = { ee 8a [2] 9a 92 [2] dd 90 [2] 9a 81 [2] d4 8d [2] d8 87 [2] cf 8c [2] d4 c2 [2] e9 }

  condition:
    any of them
}