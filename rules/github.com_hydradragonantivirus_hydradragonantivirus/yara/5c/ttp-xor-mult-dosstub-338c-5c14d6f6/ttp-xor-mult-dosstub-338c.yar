rule TTP_XOR_MULT_DOSStub_338c {
  strings:
    $key_338c = { 67 e4 [2] 13 fc [2] 54 fe [2] 13 ef [2] 5d e3 [2] 51 e9 [2] 46 e2 [2] 5d ac [2] 60 }

  condition:
    any of them
}