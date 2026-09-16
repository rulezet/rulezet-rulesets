rule TTP_XOR_MULT_DOSStub_72cb {
  strings:
    $key_72cb = { 26 a3 [2] 52 bb [2] 15 b9 [2] 52 a8 [2] 1c a4 [2] 10 ae [2] 07 a5 [2] 1c eb [2] 21 }

  condition:
    any of them
}