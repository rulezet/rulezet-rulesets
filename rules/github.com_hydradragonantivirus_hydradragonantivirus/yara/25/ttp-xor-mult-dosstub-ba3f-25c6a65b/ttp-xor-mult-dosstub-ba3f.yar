rule TTP_XOR_MULT_DOSStub_ba3f {
  strings:
    $key_ba3f = { ee 57 [2] 9a 4f [2] dd 4d [2] 9a 5c [2] d4 50 [2] d8 5a [2] cf 51 [2] d4 1f [2] e9 }

  condition:
    any of them
}