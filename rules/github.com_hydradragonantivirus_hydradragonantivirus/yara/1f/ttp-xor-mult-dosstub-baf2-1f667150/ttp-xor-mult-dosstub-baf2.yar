rule TTP_XOR_MULT_DOSStub_baf2 {
  strings:
    $key_baf2 = { ee 9a [2] 9a 82 [2] dd 80 [2] 9a 91 [2] d4 9d [2] d8 97 [2] cf 9c [2] d4 d2 [2] e9 }

  condition:
    any of them
}