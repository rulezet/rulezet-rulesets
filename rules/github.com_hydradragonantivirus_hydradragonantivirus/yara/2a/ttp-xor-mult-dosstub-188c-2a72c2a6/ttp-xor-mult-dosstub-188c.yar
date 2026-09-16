rule TTP_XOR_MULT_DOSStub_188c {
  strings:
    $key_188c = { 4c e4 [2] 38 fc [2] 7f fe [2] 38 ef [2] 76 e3 [2] 7a e9 [2] 6d e2 [2] 76 ac [2] 4b }

  condition:
    any of them
}