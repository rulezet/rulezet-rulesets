rule TTP_XOR_MULT_DOSStub_61cb {
  strings:
    $key_61cb = { 35 a3 [2] 41 bb [2] 06 b9 [2] 41 a8 [2] 0f a4 [2] 03 ae [2] 14 a5 [2] 0f eb [2] 32 }

  condition:
    any of them
}