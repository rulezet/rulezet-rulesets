rule TTP_XOR_MULT_DOSStub_66de {
  strings:
    $key_66de = { 32 b6 [2] 46 ae [2] 01 ac [2] 46 bd [2] 08 b1 [2] 04 bb [2] 13 b0 [2] 08 fe [2] 35 }

  condition:
    any of them
}