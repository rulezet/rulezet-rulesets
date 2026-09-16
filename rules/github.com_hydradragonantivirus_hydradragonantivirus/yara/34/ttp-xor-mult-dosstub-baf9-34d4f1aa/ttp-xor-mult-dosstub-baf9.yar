rule TTP_XOR_MULT_DOSStub_baf9 {
  strings:
    $key_baf9 = { ee 91 [2] 9a 89 [2] dd 8b [2] 9a 9a [2] d4 96 [2] d8 9c [2] cf 97 [2] d4 d9 [2] e9 }

  condition:
    any of them
}