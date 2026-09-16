rule TTP_XOR_MULT_DOSStub_baea {
  strings:
    $key_baea = { ee 82 [2] 9a 9a [2] dd 98 [2] 9a 89 [2] d4 85 [2] d8 8f [2] cf 84 [2] d4 ca [2] e9 }

  condition:
    any of them
}