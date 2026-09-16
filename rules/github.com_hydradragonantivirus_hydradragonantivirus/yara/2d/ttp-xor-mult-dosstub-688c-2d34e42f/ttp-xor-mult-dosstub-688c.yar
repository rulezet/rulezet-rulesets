rule TTP_XOR_MULT_DOSStub_688c {
  strings:
    $key_688c = { 3c e4 [2] 48 fc [2] 0f fe [2] 48 ef [2] 06 e3 [2] 0a e9 [2] 1d e2 [2] 06 ac [2] 3b }

  condition:
    any of them
}