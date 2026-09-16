rule TTP_XOR_MULT_DOSStub_ba09 {
  strings:
    $key_ba09 = { ee 61 [2] 9a 79 [2] dd 7b [2] 9a 6a [2] d4 66 [2] d8 6c [2] cf 67 [2] d4 29 [2] e9 }

  condition:
    any of them
}