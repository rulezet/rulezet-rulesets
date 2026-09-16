rule TTP_XOR_MULT_DOSStub_37cb {
  strings:
    $key_37cb = { 63 a3 [2] 17 bb [2] 50 b9 [2] 17 a8 [2] 59 a4 [2] 55 ae [2] 42 a5 [2] 59 eb [2] 64 }

  condition:
    any of them
}