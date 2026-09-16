rule TTP_XOR_MULT_DOSStub_ba62 {
  strings:
    $key_ba62 = { ee 0a [2] 9a 12 [2] dd 10 [2] 9a 01 [2] d4 0d [2] d8 07 [2] cf 0c [2] d4 42 [2] e9 }

  condition:
    any of them
}