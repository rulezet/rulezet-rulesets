rule TTP_XOR_MULT_DOSStub_ba23 {
  strings:
    $key_ba23 = { ee 4b [2] 9a 53 [2] dd 51 [2] 9a 40 [2] d4 4c [2] d8 46 [2] cf 4d [2] d4 03 [2] e9 }

  condition:
    any of them
}