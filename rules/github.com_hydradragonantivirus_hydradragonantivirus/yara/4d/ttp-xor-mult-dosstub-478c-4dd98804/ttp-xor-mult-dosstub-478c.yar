rule TTP_XOR_MULT_DOSStub_478c {
  strings:
    $key_478c = { 13 e4 [2] 67 fc [2] 20 fe [2] 67 ef [2] 29 e3 [2] 25 e9 [2] 32 e2 [2] 29 ac [2] 14 }

  condition:
    any of them
}