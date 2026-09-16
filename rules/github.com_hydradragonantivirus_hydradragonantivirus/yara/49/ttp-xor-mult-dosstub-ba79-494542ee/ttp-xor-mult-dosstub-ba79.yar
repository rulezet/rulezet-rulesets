rule TTP_XOR_MULT_DOSStub_ba79 {
  strings:
    $key_ba79 = { ee 11 [2] 9a 09 [2] dd 0b [2] 9a 1a [2] d4 16 [2] d8 1c [2] cf 17 [2] d4 59 [2] e9 }

  condition:
    any of them
}