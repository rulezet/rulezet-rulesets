rule TTP_XOR_MULT_DOSStub_ba0f {
  strings:
    $key_ba0f = { ee 67 [2] 9a 7f [2] dd 7d [2] 9a 6c [2] d4 60 [2] d8 6a [2] cf 61 [2] d4 2f [2] e9 }

  condition:
    any of them
}