rule TTP_XOR_MULT_DOSStub_ba0d {
  strings:
    $key_ba0d = { ee 65 [2] 9a 7d [2] dd 7f [2] 9a 6e [2] d4 62 [2] d8 68 [2] cf 63 [2] d4 2d [2] e9 }

  condition:
    any of them
}