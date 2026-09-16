rule TTP_XOR_MULT_DOSStub_50cb {
  strings:
    $key_50cb = { 04 a3 [2] 70 bb [2] 37 b9 [2] 70 a8 [2] 3e a4 [2] 32 ae [2] 25 a5 [2] 3e eb [2] 03 }

  condition:
    any of them
}