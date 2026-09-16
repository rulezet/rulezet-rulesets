rule TTP_XOR_MULT_DOSStub_278c {
  strings:
    $key_278c = { 73 e4 [2] 07 fc [2] 40 fe [2] 07 ef [2] 49 e3 [2] 45 e9 [2] 52 e2 [2] 49 ac [2] 74 }

  condition:
    any of them
}