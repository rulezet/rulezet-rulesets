rule TTP_XOR_MULT_DOSStub_ba50 {
  strings:
    $key_ba50 = { ee 38 [2] 9a 20 [2] dd 22 [2] 9a 33 [2] d4 3f [2] d8 35 [2] cf 3e [2] d4 70 [2] e9 }

  condition:
    any of them
}