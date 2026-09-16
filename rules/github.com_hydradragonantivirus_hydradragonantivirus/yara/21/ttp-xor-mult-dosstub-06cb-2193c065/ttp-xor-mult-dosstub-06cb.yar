rule TTP_XOR_MULT_DOSStub_06cb {
  strings:
    $key_06cb = { 52 a3 [2] 26 bb [2] 61 b9 [2] 26 a8 [2] 68 a4 [2] 64 ae [2] 73 a5 [2] 68 eb [2] 55 }

  condition:
    any of them
}