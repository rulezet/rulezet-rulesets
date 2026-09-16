rule TTP_XOR_MULT_DOSStub_bae3 {
  strings:
    $key_bae3 = { ee 8b [2] 9a 93 [2] dd 91 [2] 9a 80 [2] d4 8c [2] d8 86 [2] cf 8d [2] d4 c3 [2] e9 }

  condition:
    any of them
}