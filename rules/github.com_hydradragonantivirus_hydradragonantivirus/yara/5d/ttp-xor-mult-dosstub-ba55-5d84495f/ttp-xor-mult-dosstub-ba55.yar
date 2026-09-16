rule TTP_XOR_MULT_DOSStub_ba55 {
  strings:
    $key_ba55 = { ee 3d [2] 9a 25 [2] dd 27 [2] 9a 36 [2] d4 3a [2] d8 30 [2] cf 3b [2] d4 75 [2] e9 }

  condition:
    any of them
}