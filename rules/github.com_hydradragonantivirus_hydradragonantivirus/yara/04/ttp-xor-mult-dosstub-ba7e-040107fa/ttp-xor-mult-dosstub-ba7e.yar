rule TTP_XOR_MULT_DOSStub_ba7e {
  strings:
    $key_ba7e = { ee 16 [2] 9a 0e [2] dd 0c [2] 9a 1d [2] d4 11 [2] d8 1b [2] cf 10 [2] d4 5e [2] e9 }

  condition:
    any of them
}