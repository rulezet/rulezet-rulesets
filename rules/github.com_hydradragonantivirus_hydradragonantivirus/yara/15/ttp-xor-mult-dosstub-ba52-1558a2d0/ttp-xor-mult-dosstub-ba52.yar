rule TTP_XOR_MULT_DOSStub_ba52 {
  strings:
    $key_ba52 = { ee 3a [2] 9a 22 [2] dd 20 [2] 9a 31 [2] d4 3d [2] d8 37 [2] cf 3c [2] d4 72 [2] e9 }

  condition:
    any of them
}