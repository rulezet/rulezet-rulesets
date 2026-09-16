rule TTP_XOR_MULT_DOSStub_ba6c {
  strings:
    $key_ba6c = { ee 04 [2] 9a 1c [2] dd 1e [2] 9a 0f [2] d4 03 [2] d8 09 [2] cf 02 [2] d4 4c [2] e9 }

  condition:
    any of them
}