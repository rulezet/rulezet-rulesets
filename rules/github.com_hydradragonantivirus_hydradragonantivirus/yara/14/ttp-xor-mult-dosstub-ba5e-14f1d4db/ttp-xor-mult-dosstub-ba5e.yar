rule TTP_XOR_MULT_DOSStub_ba5e {
  strings:
    $key_ba5e = { ee 36 [2] 9a 2e [2] dd 2c [2] 9a 3d [2] d4 31 [2] d8 3b [2] cf 30 [2] d4 7e [2] e9 }

  condition:
    any of them
}