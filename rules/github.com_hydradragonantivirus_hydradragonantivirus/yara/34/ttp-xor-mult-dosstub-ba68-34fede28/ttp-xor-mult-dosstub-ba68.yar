rule TTP_XOR_MULT_DOSStub_ba68 {
  strings:
    $key_ba68 = { ee 00 [2] 9a 18 [2] dd 1a [2] 9a 0b [2] d4 07 [2] d8 0d [2] cf 06 [2] d4 48 [2] e9 }

  condition:
    any of them
}