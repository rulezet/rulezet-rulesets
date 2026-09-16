rule TTP_XOR_MULT_DOSStub_ba5d {
  strings:
    $key_ba5d = { ee 35 [2] 9a 2d [2] dd 2f [2] 9a 3e [2] d4 32 [2] d8 38 [2] cf 33 [2] d4 7d [2] e9 }

  condition:
    any of them
}