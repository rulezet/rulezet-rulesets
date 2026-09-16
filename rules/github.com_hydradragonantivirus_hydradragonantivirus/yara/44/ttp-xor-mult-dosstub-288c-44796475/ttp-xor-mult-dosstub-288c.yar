rule TTP_XOR_MULT_DOSStub_288c {
  strings:
    $key_288c = { 7c e4 [2] 08 fc [2] 4f fe [2] 08 ef [2] 46 e3 [2] 4a e9 [2] 5d e2 [2] 46 ac [2] 7b }

  condition:
    any of them
}