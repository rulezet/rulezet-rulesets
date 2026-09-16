rule TTP_XOR_MULT_DOSStub_ba01 {
  strings:
    $key_ba01 = { ee 69 [2] 9a 71 [2] dd 73 [2] 9a 62 [2] d4 6e [2] d8 64 [2] cf 6f [2] d4 21 [2] e9 }

  condition:
    any of them
}