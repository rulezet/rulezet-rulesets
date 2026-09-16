rule TTP_XOR_MULT_DOSStub_baf3 {
  strings:
    $key_baf3 = { ee 9b [2] 9a 83 [2] dd 81 [2] 9a 90 [2] d4 9c [2] d8 96 [2] cf 9d [2] d4 d3 [2] e9 }

  condition:
    any of them
}