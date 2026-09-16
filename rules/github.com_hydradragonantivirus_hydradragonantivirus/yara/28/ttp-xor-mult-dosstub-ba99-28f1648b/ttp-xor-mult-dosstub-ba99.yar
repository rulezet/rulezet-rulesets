rule TTP_XOR_MULT_DOSStub_ba99 {
  strings:
    $key_ba99 = { ee f1 [2] 9a e9 [2] dd eb [2] 9a fa [2] d4 f6 [2] d8 fc [2] cf f7 [2] d4 b9 [2] e9 }

  condition:
    any of them
}