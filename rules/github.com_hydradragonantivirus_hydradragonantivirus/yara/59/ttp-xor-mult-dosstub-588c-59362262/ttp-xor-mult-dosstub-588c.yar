rule TTP_XOR_MULT_DOSStub_588c {
  strings:
    $key_588c = { 0c e4 [2] 78 fc [2] 3f fe [2] 78 ef [2] 36 e3 [2] 3a e9 [2] 2d e2 [2] 36 ac [2] 0b }

  condition:
    any of them
}