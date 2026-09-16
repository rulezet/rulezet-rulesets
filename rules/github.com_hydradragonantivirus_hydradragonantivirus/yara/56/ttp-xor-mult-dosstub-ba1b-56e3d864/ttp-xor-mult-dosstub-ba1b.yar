rule TTP_XOR_MULT_DOSStub_ba1b {
  strings:
    $key_ba1b = { ee 73 [2] 9a 6b [2] dd 69 [2] 9a 78 [2] d4 74 [2] d8 7e [2] cf 75 [2] d4 3b [2] e9 }

  condition:
    any of them
}