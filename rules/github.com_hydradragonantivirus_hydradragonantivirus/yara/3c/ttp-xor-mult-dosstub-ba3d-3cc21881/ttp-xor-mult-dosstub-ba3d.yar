rule TTP_XOR_MULT_DOSStub_ba3d {
  strings:
    $key_ba3d = { ee 55 [2] 9a 4d [2] dd 4f [2] 9a 5e [2] d4 52 [2] d8 58 [2] cf 53 [2] d4 1d [2] e9 }

  condition:
    any of them
}