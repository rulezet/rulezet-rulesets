rule TTP_XOR_MULT_DOSStub_baf4 {
  strings:
    $key_baf4 = { ee 9c [2] 9a 84 [2] dd 86 [2] 9a 97 [2] d4 9b [2] d8 91 [2] cf 9a [2] d4 d4 [2] e9 }

  condition:
    any of them
}