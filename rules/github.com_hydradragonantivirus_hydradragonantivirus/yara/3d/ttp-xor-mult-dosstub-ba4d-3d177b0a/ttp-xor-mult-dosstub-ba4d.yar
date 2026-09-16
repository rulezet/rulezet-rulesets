rule TTP_XOR_MULT_DOSStub_ba4d {
  strings:
    $key_ba4d = { ee 25 [2] 9a 3d [2] dd 3f [2] 9a 2e [2] d4 22 [2] d8 28 [2] cf 23 [2] d4 6d [2] e9 }

  condition:
    any of them
}