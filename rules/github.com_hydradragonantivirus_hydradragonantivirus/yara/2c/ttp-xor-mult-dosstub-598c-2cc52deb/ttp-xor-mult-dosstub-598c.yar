rule TTP_XOR_MULT_DOSStub_598c {
  strings:
    $key_598c = { 0d e4 [2] 79 fc [2] 3e fe [2] 79 ef [2] 37 e3 [2] 3b e9 [2] 2c e2 [2] 37 ac [2] 0a }

  condition:
    any of them
}