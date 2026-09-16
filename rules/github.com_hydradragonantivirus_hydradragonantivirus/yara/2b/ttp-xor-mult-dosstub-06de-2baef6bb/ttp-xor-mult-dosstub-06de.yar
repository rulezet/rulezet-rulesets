rule TTP_XOR_MULT_DOSStub_06de {
  strings:
    $key_06de = { 52 b6 [2] 26 ae [2] 61 ac [2] 26 bd [2] 68 b1 [2] 64 bb [2] 73 b0 [2] 68 fe [2] 55 }

  condition:
    any of them
}