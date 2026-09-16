rule TTP_XOR_MULT_DOSStub_408c {
  strings:
    $key_408c = { 14 e4 [2] 60 fc [2] 27 fe [2] 60 ef [2] 2e e3 [2] 22 e9 [2] 35 e2 [2] 2e ac [2] 13 }

  condition:
    any of them
}