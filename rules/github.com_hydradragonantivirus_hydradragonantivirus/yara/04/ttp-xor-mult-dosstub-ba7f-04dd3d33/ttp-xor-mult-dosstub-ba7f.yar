rule TTP_XOR_MULT_DOSStub_ba7f {
  strings:
    $key_ba7f = { ee 17 [2] 9a 0f [2] dd 0d [2] 9a 1c [2] d4 10 [2] d8 1a [2] cf 11 [2] d4 5f [2] e9 }

  condition:
    any of them
}